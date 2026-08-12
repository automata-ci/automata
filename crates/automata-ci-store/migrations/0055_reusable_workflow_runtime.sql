-- Activate one exact planned reusable-workflow call without ever publishing a
-- synthetic JobIR.  Parent call instances retain only a runtime-context object
-- descriptor and open one transaction-local window in which the exact planned
-- child invocation, jobs, and dependencies are copied into active orchestration.

ALTER TABLE workflow_plan_v2_reusable_invocation_expansions
    ADD CONSTRAINT workflow_plan_v2_reusable_expansion_runtime_exact UNIQUE (
        run_id, parent_invocation_id, caller_logical_job_id, invocation_id
    );

-- The parent job's output aliases are a separate immutable receipt.  It may
-- be assembled once after a 0051 ledger was written, but every insert is
-- deferred against the fixed count.  A committed receipt therefore closes
-- the INSERT window just as firmly as the 0051 expansion receipt.
CREATE TABLE workflow_plan_v2_reusable_call_output_contracts (
    run_id UUID NOT NULL,
    child_invocation_id UUID NOT NULL,
    mapping_count INTEGER NOT NULL,
    mapping_digest BYTEA NOT NULL,
    bound_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_call_output_contracts_pk
        PRIMARY KEY (run_id, child_invocation_id),
    CONSTRAINT workflow_plan_v2_reusable_call_output_contracts_expansion_fk
        FOREIGN KEY (run_id, child_invocation_id)
        REFERENCES workflow_plan_v2_reusable_invocation_expansions(
            run_id, invocation_id
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_output_contracts_count CHECK (
        mapping_count BETWEEN 0 AND 256
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_output_contracts_digest CHECK (
        octet_length(mapping_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_output_contracts_time CHECK (
        bound_at_ms >= 0
    )
);

CREATE TABLE workflow_plan_v2_reusable_call_output_mappings (
    run_id UUID NOT NULL,
    child_invocation_id UUID NOT NULL,
    parent_output_name TEXT COLLATE "C" NOT NULL,
    child_output_name TEXT COLLATE "C" NOT NULL,
    sensitivity TEXT NOT NULL,
    source_order INTEGER NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_call_output_mappings_pk PRIMARY KEY (
        run_id, child_invocation_id, parent_output_name
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_output_mappings_order_unique
        UNIQUE (run_id, child_invocation_id, source_order),
    CONSTRAINT workflow_plan_v2_reusable_call_output_mappings_child_fk
        FOREIGN KEY (run_id, child_invocation_id)
        REFERENCES workflow_plan_v2_reusable_call_output_contracts(
            run_id, child_invocation_id
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_output_mappings_output_fk
        FOREIGN KEY (run_id, child_invocation_id, child_output_name)
        REFERENCES workflow_plan_v2_reusable_outputs(
            run_id, invocation_id, output_key
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_output_mappings_names CHECK (
        octet_length(parent_output_name) BETWEEN 1 AND 256
        AND octet_length(child_output_name) BETWEEN 1 AND 256
        AND btrim(parent_output_name) = parent_output_name
        AND btrim(child_output_name) = child_output_name
        AND parent_output_name !~ '[[:cntrl:]]'
        AND child_output_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_output_mappings_sensitivity CHECK (
        sensitivity IN ('public', 'secret_derived')
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_output_mappings_order CHECK (
        source_order BETWEEN 0 AND 255
    )
);

CREATE FUNCTION automata_lock_reusable_call_output_contract()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN workflow_plan_v2_reusable_invocation_expansions AS expansion
      ON expansion.run_id = marker.run_id
     AND expansion.invocation_id = NEW.child_invocation_id
    WHERE marker.run_id = NEW.run_id
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND marker.state IN ('pending', 'active')
      AND run.status IN ('queued', 'in_progress')
      AND expansion.depth > 0
      AND NOT EXISTS (
          SELECT 1 FROM workflow_plan_v2_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR UPDATE OF marker, run;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable call output contract lacks a live planned call'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_output_contract_window';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_reusable_output_contracts_00_lock
BEFORE INSERT ON workflow_plan_v2_reusable_call_output_contracts
FOR EACH ROW EXECUTE FUNCTION automata_lock_reusable_call_output_contract();

CREATE FUNCTION automata_validate_reusable_call_output_contract()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_call_output_contracts AS contract
        WHERE contract.run_id = NEW.run_id
          AND contract.child_invocation_id = NEW.child_invocation_id
          AND contract.mapping_count = (
              SELECT count(*)
              FROM workflow_plan_v2_reusable_call_output_mappings AS mapping
              WHERE mapping.run_id = contract.run_id
                AND mapping.child_invocation_id = contract.child_invocation_id
          )
    ) OR EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_call_output_mappings AS mapping
        JOIN workflow_plan_v2_reusable_outputs AS callee
          ON callee.run_id = mapping.run_id
         AND callee.invocation_id = mapping.child_invocation_id
         AND callee.output_key = mapping.child_output_name
        WHERE mapping.run_id = NEW.run_id
          AND mapping.child_invocation_id = NEW.child_invocation_id
          AND mapping.sensitivity = 'public'
          AND callee.sensitivity = 'secret_derived'
    ) THEN
        RAISE EXCEPTION 'reusable call output aliases disagree with their fixed contract'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_output_contract_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_output_contracts_validate
AFTER INSERT ON workflow_plan_v2_reusable_call_output_contracts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_call_output_contract();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_output_mappings_validate
AFTER INSERT ON workflow_plan_v2_reusable_call_output_mappings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_call_output_contract();

-- The row is both the activation publication and its single non-runnable call
-- instance. Matrix call jobs are rejected by the exact-source planner, so one
-- callsite has exactly one stable instance identity when its condition matches.
CREATE TABLE workflow_plan_v2_reusable_call_publications (
    tenant_id TEXT COLLATE "C" NOT NULL,
    repository_id UUID NOT NULL,
    run_id UUID NOT NULL,
    parent_invocation_id UUID NOT NULL,
    caller_logical_job_id UUID NOT NULL,
    caller_instance_id UUID NOT NULL,
    child_invocation_id UUID NOT NULL,
    operation_id UUID NOT NULL UNIQUE,
    activation_generation BIGINT NOT NULL,
    activation_input_digest BYTEA NOT NULL,
    condition_matched BOOLEAN NOT NULL,
    matrix_digest BYTEA NOT NULL,
    runtime_context_digest BYTEA NOT NULL,
    runtime_context_object_key TEXT COLLATE "C" NOT NULL,
    runtime_context_size_bytes BIGINT NOT NULL,
    runtime_context_media_type TEXT COLLATE "C" NOT NULL,
    runtime_context_schema SMALLINT NOT NULL,
    permission_digest BYTEA NOT NULL,
    output_mapping_count INTEGER NOT NULL,
    output_mapping_digest BYTEA NOT NULL,
    publication_digest BYTEA NOT NULL,
    runtime_policy_revision BIGINT NOT NULL,
    runtime_policy_digest BYTEA NOT NULL,
    authority_profile TEXT COLLATE "C" NOT NULL,
    published_at_ms BIGINT NOT NULL,
    child_graph_sealed_at_ms BIGINT,
    CONSTRAINT workflow_plan_v2_reusable_call_publications_pk PRIMARY KEY (
        run_id, parent_invocation_id, caller_logical_job_id
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_publications_instance_unique
        UNIQUE (caller_instance_id),
    CONSTRAINT workflow_plan_v2_reusable_call_publications_child_unique
        UNIQUE (run_id, child_invocation_id),
    CONSTRAINT workflow_plan_v2_reusable_call_publications_repository_fk
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_publications_run_fk
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_publications_parent_job_fk
        FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_publications_plan_fk
        FOREIGN KEY (
            run_id, parent_invocation_id, caller_logical_job_id,
            child_invocation_id
        ) REFERENCES workflow_plan_v2_reusable_invocation_expansions(
            run_id, parent_invocation_id, caller_logical_job_id, invocation_id
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_publications_outputs_fk
        FOREIGN KEY (run_id, child_invocation_id)
        REFERENCES workflow_plan_v2_reusable_call_output_contracts(
            run_id, child_invocation_id
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_publications_ids_non_nil CHECK (
        parent_invocation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND caller_logical_job_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND caller_instance_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND child_invocation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND operation_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_publications_generation CHECK (
        activation_generation = 1
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_publications_digests CHECK (
        octet_length(activation_input_digest) = 32
        AND octet_length(matrix_digest) = 32
        AND octet_length(runtime_context_digest) = 32
        AND octet_length(permission_digest) = 32
        AND octet_length(output_mapping_digest) = 32
        AND octet_length(publication_digest) = 32
        AND octet_length(runtime_policy_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_publications_context CHECK (
        octet_length(runtime_context_object_key) BETWEEN 1 AND 1024
        AND runtime_context_object_key !~ '[[:cntrl:]]'
        AND left(runtime_context_object_key, 1) <> '/'
        AND runtime_context_object_key !~ '(^|/)\.\.(/|$)'
        AND runtime_context_size_bytes BETWEEN 1 AND 16777216
        AND runtime_context_media_type =
            'application/vnd.automata.job-runtime-context.protobuf'
        AND runtime_context_schema = 2
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_publications_policy CHECK (
        runtime_policy_revision > 0
        AND authority_profile = 'credential_free'
        AND output_mapping_count BETWEEN 0 AND 256
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_publications_time CHECK (
        published_at_ms >= 0
        AND (
            child_graph_sealed_at_ms IS NULL
            OR child_graph_sealed_at_ms = published_at_ms
        )
    )
);

-- Shared execution-path predicate.  Existing roots retain their exact shape;
-- a child invocation becomes eligible only through one sealed, selected call
-- publication.  Selection, preparation, activation, and materialization all
-- use this same predicate instead of independently weakening root checks.
CREATE FUNCTION automata_workflow_plan_v2_invocation_published(
    target_run_id UUID,
    target_invocation_id UUID
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        WHERE marker.run_id = target_run_id
          AND (
              marker.root_invocation_id = target_invocation_id
              OR EXISTS (
                  SELECT 1
                  FROM workflow_plan_v2_reusable_call_publications AS publication
                  JOIN workflow_runs AS run
                    ON run.id = publication.run_id
                  JOIN repositories AS repository
                    ON repository.id = run.repository_id
                   AND repository.tenant_id = publication.tenant_id
                   AND repository.id = publication.repository_id
                  JOIN workflow_plan_v2_reusable_invocation_expansions AS planned
                    ON planned.run_id = publication.run_id
                   AND planned.parent_invocation_id = publication.parent_invocation_id
                   AND planned.caller_logical_job_id = publication.caller_logical_job_id
                   AND planned.invocation_id = publication.child_invocation_id
                  JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
                    ON catalog.run_id = planned.run_id
                   AND catalog.catalog_entry_id = planned.catalog_entry_id
                  JOIN workflow_plan_v2_invocations AS child
                    ON child.run_id = planned.run_id
                   AND child.id = planned.invocation_id
                  JOIN workflow_plan_v2_jobs AS caller
                    ON caller.run_id = planned.run_id
                   AND caller.invocation_id = planned.parent_invocation_id
                   AND caller.id = planned.caller_logical_job_id
                  JOIN workflow_plan_v2_reusable_permission_snapshots AS permissions
                    ON permissions.run_id = planned.run_id
                   AND permissions.invocation_id = planned.invocation_id
                   AND permissions.permission_digest = publication.permission_digest
                  JOIN workflow_plan_v2_reusable_call_output_contracts AS output_contract
                    ON output_contract.run_id = publication.run_id
                   AND output_contract.child_invocation_id = publication.child_invocation_id
                   AND output_contract.mapping_count = publication.output_mapping_count
                   AND output_contract.mapping_digest = publication.output_mapping_digest
                  JOIN workflow_plan_v2_runtime_policy_pins AS pin
                    ON pin.run_id = publication.run_id
                   AND pin.policy_revision = publication.runtime_policy_revision
                   AND pin.policy_digest = publication.runtime_policy_digest
                  WHERE publication.run_id = marker.run_id
                    AND publication.child_invocation_id = target_invocation_id
                    AND publication.condition_matched
                    AND publication.child_graph_sealed_at_ms = publication.published_at_ms
                    AND planned.depth > 0
                    AND child.invocation_kind = 'reusable'
                    AND child.plan_digest = catalog.plan_digest
                    AND child.plan_object_key = catalog.plan_object_key
                    AND child.plan_size_bytes = catalog.plan_size_bytes
                    AND child.plan_media_type = catalog.plan_media_type
                    AND child.plan_schema = catalog.plan_schema
                    AND child.state = 'active'
                    AND caller.execution_kind = 'reusable_workflow'
                    AND caller.state = 'activated'
                    AND caller.activation_fence = publication.activation_generation
                    AND caller.activation_input_digest = publication.activation_input_digest
                    AND caller.authority_profile = publication.authority_profile
                    AND caller.activation_owner_id IS NULL
                    AND caller.activation_claimed_at_ms IS NULL
                    AND caller.activation_expires_at_ms IS NULL
                    AND caller.activation_origin_selection_id IS NULL
                    AND (SELECT count(*)
                         FROM workflow_plan_v2_jobs AS active
                         WHERE active.run_id = planned.run_id
                           AND active.invocation_id = planned.invocation_id)
                        = (SELECT count(*)
                           FROM workflow_plan_v2_reusable_expanded_jobs AS expected
                           WHERE expected.run_id = planned.run_id
                             AND expected.invocation_id = planned.invocation_id)
                    AND NOT EXISTS (
                        SELECT 1
                        FROM workflow_plan_v2_reusable_expanded_jobs AS expected
                        LEFT JOIN workflow_plan_v2_jobs AS active
                          ON active.run_id = expected.run_id
                         AND active.invocation_id = expected.invocation_id
                         AND active.id = expected.logical_job_id
                         AND active.logical_key = expected.logical_key
                         AND active.source_order = expected.source_order
                         AND active.execution_kind = expected.execution_kind
                         AND active.runtime_policy_revision = publication.runtime_policy_revision
                         AND active.runtime_policy_digest = publication.runtime_policy_digest
                        WHERE expected.run_id = planned.run_id
                          AND expected.invocation_id = planned.invocation_id
                          AND active.id IS NULL
                    )
                    AND (SELECT count(*)
                         FROM workflow_plan_v2_dependencies AS active
                         WHERE active.run_id = planned.run_id
                           AND active.invocation_id = planned.invocation_id)
                        = (SELECT count(*)
                           FROM workflow_plan_v2_reusable_expanded_dependencies AS expected
                           WHERE expected.run_id = planned.run_id
                             AND expected.invocation_id = planned.invocation_id)
                    AND NOT EXISTS (
                        SELECT 1
                        FROM workflow_plan_v2_reusable_expanded_dependencies AS expected
                        LEFT JOIN workflow_plan_v2_dependencies AS active
                          ON active.run_id = expected.run_id
                         AND active.invocation_id = expected.invocation_id
                         AND active.logical_job_id = expected.logical_job_id
                         AND active.prerequisite_job_id = expected.prerequisite_job_id
                        WHERE expected.run_id = planned.run_id
                          AND expected.invocation_id = planned.invocation_id
                          AND active.logical_job_id IS NULL
                    )
              )
          )
    )
$automata$;

-- Historical manifest authority remains exact for roots and reusable children;
-- the latter are authorized only after their immutable publication is sealed.
CREATE OR REPLACE FUNCTION automata_validate_activation_preparation_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN github_workflow_run_subject_evidence AS subject
          ON subject.tenant_id = repository.tenant_id
         AND subject.repository_id = run.repository_id
         AND subject.run_id = run.id
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery.tenant_id
         AND manifest.repository_id = delivery.repository_id
         AND manifest.provider_connection_id = delivery.provider_connection_id
         AND manifest.manifest_revision = delivery.provider_manifest_revision
         AND manifest.manifest_digest = delivery.provider_manifest_digest
        WHERE run.id = NEW.run_id
          AND automata_workflow_plan_v2_invocation_published(
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
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_logical_activation_preparation_claim()
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
      AND automata_workflow_plan_v2_invocation_published(
          marker.run_id, invocation.id
      )
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

CREATE OR REPLACE FUNCTION automata_enforce_logical_activation_preparation_claim_update()
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
          AND automata_workflow_plan_v2_invocation_published(
              marker.run_id, invocation.id
          )
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
          AND automata_workflow_plan_v2_invocation_published(
              marker.run_id, invocation.id
          )
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

CREATE OR REPLACE FUNCTION automata_require_active_unquarantined_workflow_phase(
    target_run_id UUID,
    target_invocation_id UUID,
    target_logical_job_id UUID,
    target_instance_id UUID
)
RETURNS void
LANGUAGE plpgsql
AS $automata$
DECLARE
    graph_active BOOLEAN;
BEGIN
    SELECT run.status IN ('queued', 'in_progress')
           AND run.admission_epoch = 4
           AND run.plan_schema = 2
      INTO graph_active
    FROM workflow_runs AS run
    WHERE run.id = target_run_id
    FOR SHARE OF run;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires an active run'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_run_active';
    END IF;

    SELECT marker.state IN ('pending', 'active')
           AND marker.orchestration_schema = 1
           AND marker.admission_graph_sealed_at_ms IS NOT NULL
           AND automata_workflow_plan_v2_invocation_published(
               marker.run_id, target_invocation_id
           )
      INTO graph_active
    FROM workflow_plan_v2_runs AS marker
    WHERE marker.run_id = target_run_id
    FOR SHARE OF marker;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires an active published marker'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_marker_active';
    END IF;

    SELECT invocation.state IN ('pending', 'active')
           AND invocation.plan_schema = 2
      INTO graph_active
    FROM workflow_plan_v2_invocations AS invocation
    WHERE invocation.run_id = target_run_id
      AND invocation.id = target_invocation_id
    FOR SHARE OF invocation;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires an active invocation'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_invocation_active';
    END IF;

    SELECT TRUE INTO graph_active
    FROM workflow_plan_v2_jobs AS job
    WHERE job.run_id = target_run_id
      AND job.invocation_id = target_invocation_id
      AND job.id = target_logical_job_id
    FOR SHARE OF job;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires its exact logical job'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_logical_job_exact';
    END IF;

    IF target_instance_id IS NOT NULL THEN
        SELECT TRUE INTO graph_active
        FROM workflow_plan_v2_instances AS instance
        WHERE instance.id = target_instance_id
          AND instance.run_id = target_run_id
          AND instance.invocation_id = target_invocation_id
          AND instance.logical_job_id = target_logical_job_id
        FOR SHARE OF instance;
        IF graph_active IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'workflow phase mutation requires its exact instance'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_phase_instance_exact';
        END IF;
    END IF;

    IF target_instance_id IS NULL THEN
        PERFORM 1
        FROM workflow_plan_v2_activation_work_quarantines AS quarantine
        WHERE quarantine.logical_job_id = target_logical_job_id
        FOR SHARE OF quarantine;
    ELSE
        PERFORM 1
        FROM workflow_plan_v2_materialization_work_quarantines AS quarantine
        WHERE quarantine.instance_id = target_instance_id
        FOR SHARE OF quarantine;
    END IF;
    IF FOUND THEN
        RAISE EXCEPTION 'workflow phase mutation is quarantined'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_quarantine_dominates';
    END IF;
END;
$automata$;

CREATE FUNCTION automata_lock_reusable_call_publication()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    JOIN workflow_plan_v2_invocations AS parent
      ON parent.run_id = marker.run_id
     AND parent.id = NEW.parent_invocation_id
    JOIN workflow_plan_v2_jobs AS caller
      ON caller.run_id = parent.run_id
     AND caller.invocation_id = parent.id
     AND caller.id = NEW.caller_logical_job_id
    JOIN workflow_plan_v2_runtime_policy_pins AS pin
      ON pin.run_id = marker.run_id
    JOIN workflow_plan_v2_reusable_invocation_expansions AS planned
      ON planned.run_id = caller.run_id
     AND planned.parent_invocation_id = caller.invocation_id
     AND planned.caller_logical_job_id = caller.id
     AND planned.invocation_id = NEW.child_invocation_id
    JOIN workflow_plan_v2_reusable_permission_snapshots AS permissions
      ON permissions.run_id = planned.run_id
     AND permissions.invocation_id = planned.invocation_id
    JOIN workflow_plan_v2_reusable_call_output_contracts AS output_contract
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
          FROM workflow_plan_v2_dependencies AS dependency
          LEFT JOIN workflow_plan_v2_job_results AS result
            ON result.run_id = dependency.run_id
           AND result.invocation_id = dependency.invocation_id
           AND result.logical_job_id = dependency.prerequisite_job_id
          LEFT JOIN workflow_plan_v2_job_result_claims AS claim
            ON claim.logical_job_id = result.logical_job_id
           AND claim.state = 'finalized'
          WHERE dependency.run_id = caller.run_id
            AND dependency.invocation_id = caller.invocation_id
            AND dependency.logical_job_id = caller.id
            AND (result.logical_job_id IS NULL OR claim.logical_job_id IS NULL)
      )
      AND NOT EXISTS (
          SELECT 1 FROM workflow_plan_v2_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR UPDATE OF marker, run, parent, caller;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable call publication lacks a ready live parent instance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_publication_window';
    END IF;
    IF NEW.child_graph_sealed_at_ms IS NOT NULL THEN
        RAISE EXCEPTION 'reusable child graph must begin unsealed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_publication_unsealed';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_reusable_calls_00_lock
BEFORE INSERT ON workflow_plan_v2_reusable_call_publications
FOR EACH ROW EXECUTE FUNCTION automata_lock_reusable_call_publication();

-- Root admission remains unchanged. A child graph is writable only while its
-- own publication row is unsealed in the same transaction.
CREATE OR REPLACE FUNCTION automata_require_open_workflow_admission_graph()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN github_workflow_run_subject_evidence AS subject ON subject.run_id = marker.run_id
    JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND subject.admitted_at_ms = receipt.committed_at_ms
      AND pin.pinned_at_ms = subject.admitted_at_ms
    FOR KEY SHARE OF marker, receipt, subject, pin;
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

CREATE FUNCTION automata_seal_reusable_call_publication()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_publication_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_reusable_calls_seal
BEFORE UPDATE ON workflow_plan_v2_reusable_call_publications
FOR EACH ROW EXECUTE FUNCTION automata_seal_reusable_call_publication();

CREATE FUNCTION automata_validate_reusable_call_publication()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    durable workflow_plan_v2_reusable_call_publications%ROWTYPE;
BEGIN
    SELECT * INTO durable
    FROM workflow_plan_v2_reusable_call_publications AS publication
    WHERE publication.run_id = NEW.run_id
      AND publication.parent_invocation_id = NEW.parent_invocation_id
      AND publication.caller_logical_job_id = NEW.caller_logical_job_id;

    IF NOT FOUND
        OR durable.child_graph_sealed_at_ms IS NULL
        OR NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_invocation_expansions AS planned
            JOIN workflow_plan_v2_jobs AS caller
              ON caller.run_id = planned.run_id
             AND caller.invocation_id = planned.parent_invocation_id
             AND caller.id = planned.caller_logical_job_id
            WHERE planned.run_id = durable.run_id
              AND planned.invocation_id = durable.child_invocation_id
              AND planned.parent_invocation_id = durable.parent_invocation_id
              AND planned.caller_logical_job_id = durable.caller_logical_job_id
              AND caller.execution_kind = 'reusable_workflow'
              AND caller.state = CASE WHEN durable.condition_matched
                  THEN 'activated' ELSE 'skipped' END
              AND caller.activation_fence = durable.activation_generation
              AND caller.activation_input_digest = durable.activation_input_digest
              AND caller.authority_profile = durable.authority_profile
              AND caller.activation_owner_id IS NULL
              AND caller.activation_claimed_at_ms IS NULL
              AND caller.activation_expires_at_ms IS NULL
              AND caller.activation_origin_selection_id IS NULL
              AND caller.updated_at_ms = durable.published_at_ms
        )
        OR NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_call_output_contracts AS contract
            WHERE contract.run_id = durable.run_id
              AND contract.child_invocation_id = durable.child_invocation_id
              AND contract.mapping_count = durable.output_mapping_count
              AND contract.mapping_digest = durable.output_mapping_digest
        )
        OR (durable.condition_matched AND NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_invocation_expansions AS planned
            JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
              ON catalog.run_id = planned.run_id
             AND catalog.catalog_entry_id = planned.catalog_entry_id
            JOIN workflow_plan_v2_invocations AS child
              ON child.run_id = planned.run_id
             AND child.id = planned.invocation_id
            WHERE planned.run_id = durable.run_id
              AND planned.invocation_id = durable.child_invocation_id
              AND child.invocation_kind = 'reusable'
              AND child.plan_digest = catalog.plan_digest
              AND child.plan_object_key = catalog.plan_object_key
              AND child.plan_size_bytes = catalog.plan_size_bytes
              AND child.plan_media_type = catalog.plan_media_type
              AND child.plan_schema = catalog.plan_schema
              AND child.state = 'active'
        ))
        OR (durable.condition_matched AND (SELECT count(*)
            FROM workflow_plan_v2_jobs
            WHERE run_id = durable.run_id
              AND invocation_id = durable.child_invocation_id)
           <> (SELECT count(*)
               FROM workflow_plan_v2_reusable_expanded_jobs
               WHERE run_id = durable.run_id
                 AND invocation_id = durable.child_invocation_id))
        OR (durable.condition_matched AND EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_expanded_jobs AS planned
            LEFT JOIN workflow_plan_v2_jobs AS active
              ON active.run_id = planned.run_id
             AND active.invocation_id = planned.invocation_id
             AND active.id = planned.logical_job_id
             AND active.logical_key = planned.logical_key
             AND active.source_order = planned.source_order
             AND active.execution_kind = planned.execution_kind
             AND active.state = 'pending'
             AND active.activation_fence = 0
             AND active.runtime_policy_revision = durable.runtime_policy_revision
             AND active.runtime_policy_digest = durable.runtime_policy_digest
            WHERE planned.run_id = durable.run_id
              AND planned.invocation_id = durable.child_invocation_id
              AND active.id IS NULL
        ))
        OR (durable.condition_matched AND (SELECT count(*)
            FROM workflow_plan_v2_dependencies
            WHERE run_id = durable.run_id
              AND invocation_id = durable.child_invocation_id)
           <> (SELECT count(*)
               FROM workflow_plan_v2_reusable_expanded_dependencies
               WHERE run_id = durable.run_id
                 AND invocation_id = durable.child_invocation_id))
        OR (durable.condition_matched AND EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_expanded_dependencies AS planned
            LEFT JOIN workflow_plan_v2_dependencies AS active
              ON active.run_id = planned.run_id
             AND active.invocation_id = planned.invocation_id
             AND active.logical_job_id = planned.logical_job_id
             AND active.prerequisite_job_id = planned.prerequisite_job_id
            WHERE planned.run_id = durable.run_id
              AND planned.invocation_id = durable.child_invocation_id
              AND active.logical_job_id IS NULL
        ))
        OR (NOT durable.condition_matched AND EXISTS (
            SELECT 1
            FROM workflow_plan_v2_invocations AS child
            WHERE child.run_id = durable.run_id
              AND child.id = durable.child_invocation_id
        ))
    THEN
        RAISE EXCEPTION 'reusable call publication did not seal its exact child graph'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_graph_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_calls_validate
AFTER INSERT OR UPDATE ON workflow_plan_v2_reusable_call_publications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_call_publication();

-- A reusable call does not execute user code in the parent job and therefore
-- never fabricates a preparation claim or JobIR.  The sealed publication is
-- the sole evidence allowed to bind the credential-free authority profile.
CREATE OR REPLACE FUNCTION automata_enforce_logical_job_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.authority_profile IS NOT NULL
        AND NEW.authority_profile IS DISTINCT FROM OLD.authority_profile
    THEN
        RAISE EXCEPTION 'logical job authority profile is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_jobs_authority_profile_immutable';
    END IF;
    IF OLD.authority_profile IS NULL AND NEW.authority_profile IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_preparation_claims AS claim
            WHERE claim.logical_job_id = NEW.id
              AND claim.run_id = NEW.run_id
              AND claim.invocation_id = NEW.invocation_id
              AND claim.authority_profile = NEW.authority_profile
        )
        AND NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_call_publications AS publication
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
                  CONSTRAINT = 'workflow_plan_v2_jobs_authority_profile_binding';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_enforce_activation_claim_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
           FROM workflow_plan_v2_reusable_call_publications AS publication
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
           FROM workflow_plan_v2_concurrency_cancellations AS cancellation
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
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_activation_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.state = 'pending'
        AND NEW.state IN ('activated', 'skipped')
        AND EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_call_publications AS publication
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
    THEN
        RETURN NEW;
    END IF;

    IF NEW.state IN ('completed', 'failed', 'cancelled', 'skipped')
        AND NEW.state IS DISTINCT FROM OLD.state
        AND OLD.state IN ('activated', 'skipped')
        AND EXISTS (
            SELECT 1
            FROM workflow_plan_v2_job_results AS result
            WHERE result.run_id = NEW.run_id
              AND result.invocation_id = NEW.invocation_id
              AND result.logical_job_id = NEW.id
              AND result.finalized_at_ms = NEW.updated_at_ms
              AND NEW.state = CASE result.effective_conclusion
                  WHEN 'success' THEN 'completed'
                  WHEN 'failure' THEN 'failed'
                  WHEN 'timed_out' THEN 'failed'
                  WHEN 'cancelled' THEN 'cancelled'
                  WHEN 'skipped' THEN 'skipped'
              END
        )
    THEN
        RETURN NEW;
    END IF;

    IF NEW.state IN ('activated', 'skipped')
        AND NEW.state IS DISTINCT FROM OLD.state
        AND NOT (
            OLD.state = 'activating'
            AND NEW.activation_owner_id IS NULL
            AND NEW.activation_claimed_at_ms IS NULL
            AND NEW.activation_expires_at_ms IS NULL
            AND EXISTS (
                SELECT 1
                FROM workflow_plan_v2_activation_publications AS publication
                WHERE publication.run_id = NEW.run_id
                  AND publication.invocation_id = NEW.invocation_id
                  AND publication.logical_job_id = NEW.id
                  AND publication.activation_owner_id = OLD.activation_owner_id
                  AND publication.activation_generation = OLD.activation_fence
                  AND publication.activation_input_digest = OLD.activation_input_digest
                  AND publication.activation_claimed_at_ms = OLD.activation_claimed_at_ms
                  AND publication.activation_expires_at_ms = OLD.activation_expires_at_ms
                  AND publication.published_at_ms = NEW.updated_at_ms
                  AND (
                      (NEW.state = 'activated' AND publication.condition_matched)
                      OR (NEW.state = 'skipped'
                          AND NOT publication.condition_matched
                          AND publication.instance_count = 0)
                  )
            )
        )
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 activation transition lacks exact publication'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Completion is a second one-way receipt.  The evaluator must load the exact
-- digest-bound child plan and evaluate its workflow_call output templates over
-- finalized child job results.  SQL retains the exact result set consumed by
-- that evaluation and checks every output key and sensitivity at COMMIT.
CREATE TABLE workflow_plan_v2_reusable_call_results (
    tenant_id TEXT COLLATE "C" NOT NULL,
    repository_id UUID NOT NULL,
    run_id UUID NOT NULL,
    parent_invocation_id UUID NOT NULL,
    caller_logical_job_id UUID NOT NULL,
    caller_instance_id UUID NOT NULL,
    child_invocation_id UUID NOT NULL,
    publication_operation_id UUID NOT NULL,
    completion_operation_id UUID NOT NULL UNIQUE,
    callee_plan_digest BYTEA NOT NULL,
    evaluator_schema SMALLINT NOT NULL,
    child_job_count INTEGER NOT NULL,
    child_jobs_digest BYTEA NOT NULL,
    workflow_output_evaluation_digest BYTEA NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    effective_conclusion TEXT NOT NULL,
    output_count INTEGER NOT NULL,
    outputs_digest BYTEA NOT NULL,
    commit_digest BYTEA NOT NULL,
    parent_result_descriptor_digest BYTEA NOT NULL,
    parent_instances_digest BYTEA NOT NULL,
    parent_prerequisites_digest BYTEA NOT NULL,
    parent_outputs_digest BYTEA NOT NULL,
    parent_commit_digest BYTEA NOT NULL,
    completed_at_ms BIGINT NOT NULL,
    sealed_at_ms BIGINT,
    CONSTRAINT workflow_plan_v2_reusable_call_results_pk PRIMARY KEY (
        run_id, parent_invocation_id, caller_logical_job_id
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_results_instance_unique
        UNIQUE (caller_instance_id),
    CONSTRAINT workflow_plan_v2_reusable_call_results_child_unique
        UNIQUE (run_id, child_invocation_id),
    CONSTRAINT workflow_plan_v2_reusable_call_results_repository_fk
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_results_run_fk
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_results_publication_fk
        FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id)
        REFERENCES workflow_plan_v2_reusable_call_publications(
            run_id, parent_invocation_id, caller_logical_job_id
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_results_ids_non_nil CHECK (
        caller_instance_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND child_invocation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND publication_operation_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND completion_operation_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_results_digests CHECK (
        octet_length(callee_plan_digest) = 32
        AND octet_length(child_jobs_digest) = 32
        AND octet_length(workflow_output_evaluation_digest) = 32
        AND octet_length(descriptor_digest) = 32
        AND octet_length(outputs_digest) = 32
        AND octet_length(commit_digest) = 32
        AND octet_length(parent_result_descriptor_digest) = 32
        AND octet_length(parent_instances_digest) = 32
        AND octet_length(parent_prerequisites_digest) = 32
        AND octet_length(parent_outputs_digest) = 32
        AND octet_length(parent_commit_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_results_shape CHECK (
        evaluator_schema = 1
        AND child_job_count BETWEEN 0 AND 4096
        AND output_count BETWEEN 0 AND 256
        AND effective_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
        AND completed_at_ms >= 0
        AND (sealed_at_ms IS NULL OR sealed_at_ms = completed_at_ms)
    )
);

CREATE TABLE workflow_plan_v2_reusable_call_result_jobs (
    run_id UUID NOT NULL,
    parent_invocation_id UUID NOT NULL,
    caller_logical_job_id UUID NOT NULL,
    child_logical_job_id UUID NOT NULL,
    source_order INTEGER NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    outputs_digest BYTEA NOT NULL,
    commit_digest BYTEA NOT NULL,
    effective_conclusion TEXT NOT NULL,
    closure_has_failure BOOLEAN NOT NULL,
    closure_has_cancelled BOOLEAN NOT NULL,
    closure_has_skipped BOOLEAN NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_call_result_jobs_pk PRIMARY KEY (
        run_id, parent_invocation_id, caller_logical_job_id,
        child_logical_job_id
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_result_jobs_order_unique UNIQUE (
        run_id, parent_invocation_id, caller_logical_job_id, source_order
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_result_jobs_result_fk
        FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id)
        REFERENCES workflow_plan_v2_reusable_call_results(
            run_id, parent_invocation_id, caller_logical_job_id
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_result_jobs_shape CHECK (
        child_logical_job_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND source_order BETWEEN 0 AND 1023
        AND octet_length(descriptor_digest) = 32
        AND octet_length(outputs_digest) = 32
        AND octet_length(commit_digest) = 32
        AND effective_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
    )
);

CREATE TABLE workflow_plan_v2_reusable_call_result_outputs (
    run_id UUID NOT NULL,
    parent_invocation_id UUID NOT NULL,
    caller_logical_job_id UUID NOT NULL,
    callee_output_name TEXT COLLATE "C" NOT NULL,
    sensitivity TEXT NOT NULL,
    public_value TEXT,
    source_order INTEGER NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_call_result_outputs_pk PRIMARY KEY (
        run_id, parent_invocation_id, caller_logical_job_id,
        callee_output_name
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_result_outputs_order_unique UNIQUE (
        run_id, parent_invocation_id, caller_logical_job_id, source_order
    ),
    CONSTRAINT workflow_plan_v2_reusable_call_result_outputs_result_fk
        FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id)
        REFERENCES workflow_plan_v2_reusable_call_results(
            run_id, parent_invocation_id, caller_logical_job_id
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_call_result_outputs_shape CHECK (
        octet_length(callee_output_name) BETWEEN 1 AND 256
        AND btrim(callee_output_name) = callee_output_name
        AND callee_output_name !~ '[[:cntrl:]]'
        AND source_order BETWEEN 0 AND 255
        AND (
            (sensitivity = 'public' AND public_value IS NOT NULL
                AND octet_length(public_value) <= 2097152)
            OR (sensitivity = 'secret_derived' AND public_value IS NULL)
        )
    )
);

CREATE FUNCTION automata_lock_reusable_call_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    matched BOOLEAN;
    expected_conclusion TEXT;
BEGIN
    SELECT publication.condition_matched
      INTO matched
    FROM workflow_plan_v2_reusable_call_publications AS publication
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = publication.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    JOIN workflow_plan_v2_jobs AS caller
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
          SELECT 1 FROM workflow_plan_v2_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR UPDATE OF marker, run, caller;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable call result lacks an exact live publication'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_result_window';
    END IF;

    IF NEW.sealed_at_ms IS NOT NULL THEN
        RAISE EXCEPTION 'reusable call result must begin unsealed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_result_unsealed';
    END IF;

    IF NOT matched THEN
        IF NEW.child_job_count <> 0
            OR NEW.output_count <> 0
            OR NEW.effective_conclusion <> 'skipped'
        THEN
            RAISE EXCEPTION 'skipped reusable call result is not empty'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_plan_v2_reusable_call_result_skipped';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_plan_v2_invocations AS child
    JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
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
        FROM workflow_plan_v2_jobs AS child_job
        LEFT JOIN workflow_plan_v2_job_results AS child_result
          ON child_result.run_id = child_job.run_id
         AND child_result.invocation_id = child_job.invocation_id
         AND child_result.logical_job_id = child_job.id
        LEFT JOIN workflow_plan_v2_job_result_claims AS child_claim
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
                  CONSTRAINT = 'workflow_plan_v2_reusable_child_results_complete';
    END IF;

    SELECT CASE
        WHEN bool_or(child_result.effective_conclusion = 'failure') THEN 'failure'
        WHEN bool_or(child_result.effective_conclusion = 'timed_out') THEN 'timed_out'
        WHEN bool_or(child_result.effective_conclusion = 'cancelled') THEN 'cancelled'
        WHEN bool_or(child_result.effective_conclusion = 'success') THEN 'success'
        ELSE 'skipped'
    END
      INTO expected_conclusion
    FROM workflow_plan_v2_jobs AS child_job
    JOIN workflow_plan_v2_job_results AS child_result
      ON child_result.run_id = child_job.run_id
     AND child_result.invocation_id = child_job.invocation_id
     AND child_result.logical_job_id = child_job.id
    WHERE child_job.run_id = NEW.run_id
      AND child_job.invocation_id = NEW.child_invocation_id;

    IF NEW.child_job_count <> (
            SELECT count(*) FROM workflow_plan_v2_jobs AS child_job
            WHERE child_job.run_id = NEW.run_id
              AND child_job.invocation_id = NEW.child_invocation_id
        )
        OR NEW.output_count <> (
            SELECT output_count
            FROM workflow_plan_v2_reusable_invocation_expansions AS expansion
            WHERE expansion.run_id = NEW.run_id
              AND expansion.invocation_id = NEW.child_invocation_id
        )
        OR NEW.effective_conclusion IS DISTINCT FROM expected_conclusion
    THEN
        RAISE EXCEPTION 'reusable call result aggregate is inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_result_aggregate';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_reusable_call_results_00_lock
BEFORE INSERT ON workflow_plan_v2_reusable_call_results
FOR EACH ROW EXECUTE FUNCTION automata_lock_reusable_call_result();

CREATE FUNCTION automata_seal_reusable_call_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_result_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_reusable_call_results_seal
BEFORE UPDATE ON workflow_plan_v2_reusable_call_results
FOR EACH ROW EXECUTE FUNCTION automata_seal_reusable_call_result();

CREATE FUNCTION automata_validate_reusable_call_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    matched BOOLEAN;
    expected_conclusion TEXT;
    durable workflow_plan_v2_reusable_call_results%ROWTYPE;
BEGIN
    SELECT * INTO durable
    FROM workflow_plan_v2_reusable_call_results AS result
    WHERE result.run_id = NEW.run_id
      AND result.parent_invocation_id = NEW.parent_invocation_id
      AND result.caller_logical_job_id = NEW.caller_logical_job_id;

    SELECT publication.condition_matched
      INTO matched
    FROM workflow_plan_v2_reusable_call_publications AS publication
    WHERE publication.run_id = NEW.run_id
      AND publication.parent_invocation_id = NEW.parent_invocation_id
      AND publication.caller_logical_job_id = NEW.caller_logical_job_id;

    IF durable.run_id IS NULL
        OR durable.sealed_at_ms IS NULL
        OR matched IS NULL
        OR durable.child_job_count <> (
            SELECT count(*)
            FROM workflow_plan_v2_reusable_call_result_jobs AS evidence
            WHERE evidence.run_id = NEW.run_id
              AND evidence.parent_invocation_id = NEW.parent_invocation_id
              AND evidence.caller_logical_job_id = NEW.caller_logical_job_id
        )
        OR durable.output_count <> (
            SELECT count(*)
            FROM workflow_plan_v2_reusable_call_result_outputs AS output
            WHERE output.run_id = NEW.run_id
              AND output.parent_invocation_id = NEW.parent_invocation_id
              AND output.caller_logical_job_id = NEW.caller_logical_job_id
        )
        OR EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_call_result_jobs AS evidence
            LEFT JOIN workflow_plan_v2_jobs AS child_job
              ON child_job.run_id = evidence.run_id
             AND child_job.invocation_id = durable.child_invocation_id
             AND child_job.id = evidence.child_logical_job_id
             AND child_job.source_order = evidence.source_order
            LEFT JOIN workflow_plan_v2_job_results AS child_result
              ON child_result.run_id = child_job.run_id
             AND child_result.invocation_id = child_job.invocation_id
             AND child_result.logical_job_id = child_job.id
             AND child_result.descriptor_digest = evidence.descriptor_digest
             AND child_result.outputs_digest = evidence.outputs_digest
             AND child_result.commit_digest = evidence.commit_digest
             AND child_result.effective_conclusion = evidence.effective_conclusion
             AND child_result.closure_has_failure = evidence.closure_has_failure
             AND child_result.closure_has_cancelled = evidence.closure_has_cancelled
             AND child_result.closure_has_skipped = evidence.closure_has_skipped
            LEFT JOIN workflow_plan_v2_job_result_claims AS child_claim
              ON child_claim.logical_job_id = child_result.logical_job_id
             AND child_claim.state = 'finalized'
            WHERE evidence.run_id = NEW.run_id
              AND evidence.parent_invocation_id = NEW.parent_invocation_id
              AND evidence.caller_logical_job_id = NEW.caller_logical_job_id
              AND (child_result.logical_job_id IS NULL
                   OR child_claim.logical_job_id IS NULL)
        )
        OR EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_call_result_outputs AS output
            LEFT JOIN workflow_plan_v2_reusable_outputs AS declared
              ON declared.run_id = output.run_id
             AND declared.invocation_id = durable.child_invocation_id
             AND declared.output_key = output.callee_output_name
             AND declared.source_order = output.source_order
             AND declared.sensitivity = output.sensitivity
            WHERE output.run_id = NEW.run_id
              AND output.parent_invocation_id = NEW.parent_invocation_id
              AND output.caller_logical_job_id = NEW.caller_logical_job_id
              AND declared.output_key IS NULL
        )
    THEN
        RAISE EXCEPTION 'reusable call result did not seal exact child evidence and outputs'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_result_exact';
    END IF;

    IF NOT matched THEN
        IF durable.child_job_count <> 0
            OR durable.output_count <> 0
            OR durable.effective_conclusion <> 'skipped'
        THEN
            RAISE EXCEPTION 'skipped reusable call result is not exact'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_plan_v2_reusable_call_result_skipped';
        END IF;
        RETURN NULL;
    END IF;

    SELECT CASE
        WHEN bool_or(evidence.effective_conclusion = 'failure') THEN 'failure'
        WHEN bool_or(evidence.effective_conclusion = 'timed_out') THEN 'timed_out'
        WHEN bool_or(evidence.effective_conclusion = 'cancelled') THEN 'cancelled'
        WHEN bool_or(evidence.effective_conclusion = 'success') THEN 'success'
        ELSE 'skipped'
    END
      INTO expected_conclusion
    FROM workflow_plan_v2_reusable_call_result_jobs AS evidence
    WHERE evidence.run_id = NEW.run_id
      AND evidence.parent_invocation_id = NEW.parent_invocation_id
      AND evidence.caller_logical_job_id = NEW.caller_logical_job_id;
    IF expected_conclusion IS DISTINCT FROM durable.effective_conclusion THEN
        RAISE EXCEPTION 'reusable call result conclusion is inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_call_result_conclusion';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_call_results_validate
AFTER INSERT OR UPDATE ON workflow_plan_v2_reusable_call_results
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_call_result();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_result_jobs_validate
AFTER INSERT ON workflow_plan_v2_reusable_call_result_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_call_result();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_result_outputs_validate
AFTER INSERT ON workflow_plan_v2_reusable_call_result_outputs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_call_result();

-- Reuse the settled logical-result tables so downstream `needs` and root-run
-- finalization observe a reusable call exactly once.  Each validator retains
-- the pre-existing step branch and adds only the sealed reusable-result branch.
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
                      JOIN workflow_plan_v2_instance_results AS instance_result
                        ON instance_result.instance_id = instance.id
                       AND instance_result.run_id = instance.run_id
                       AND instance_result.invocation_id = instance.invocation_id
                       AND instance_result.logical_job_id = instance.logical_job_id
                      JOIN workflow_plan_v2_instance_result_claims AS instance_claim
                        ON instance_claim.instance_id = instance_result.instance_id
                       AND instance_claim.state = 'finalized'
                      WHERE instance.run_id = job.run_id
                        AND instance.invocation_id = job.invocation_id
                        AND instance.logical_job_id = job.id
                  )
                  AND NEW.claimed_at_ms >= COALESCE((
                      SELECT max(instance_result.finalized_at_ms)
                      FROM workflow_plan_v2_instance_results AS instance_result
                      WHERE instance_result.run_id = job.run_id
                        AND instance_result.invocation_id = job.invocation_id
                        AND instance_result.logical_job_id = job.id
                  ), 0)
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_dependencies AS dependency
              LEFT JOIN workflow_plan_v2_job_results AS prerequisite
                ON prerequisite.logical_job_id = dependency.prerequisite_job_id
               AND prerequisite.run_id = dependency.run_id
               AND prerequisite.invocation_id = dependency.invocation_id
              LEFT JOIN workflow_plan_v2_job_result_claims AS prerequisite_claim
                ON prerequisite_claim.logical_job_id =
                    dependency.prerequisite_job_id
               AND prerequisite_claim.state = 'finalized'
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
                AND (prerequisite.logical_job_id IS NULL
                     OR prerequisite_claim.logical_job_id IS NULL
                     OR NEW.claimed_at_ms < prerequisite.finalized_at_ms)
          )
    ) AND NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN workflow_plan_v2_reusable_call_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.parent_invocation_id = job.invocation_id
         AND publication.caller_logical_job_id = job.id
        JOIN workflow_plan_v2_reusable_call_results AS call_result
          ON call_result.run_id = publication.run_id
         AND call_result.parent_invocation_id = publication.parent_invocation_id
         AND call_result.caller_logical_job_id = publication.caller_logical_job_id
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'reusable_workflow'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_schema = 2
          AND invocation.plan_media_type =
              'application/vnd.automata.workflow-plan+json'
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND publication.child_graph_sealed_at_ms IS NOT NULL
          AND call_result.sealed_at_ms IS NOT NULL
          AND call_result.parent_result_descriptor_digest = NEW.descriptor_digest
          AND NEW.claimed_at_ms >= call_result.completed_at_ms
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_dependencies AS dependency
              LEFT JOIN workflow_plan_v2_job_results AS prerequisite
                ON prerequisite.logical_job_id = dependency.prerequisite_job_id
               AND prerequisite.run_id = dependency.run_id
               AND prerequisite.invocation_id = dependency.invocation_id
              LEFT JOIN workflow_plan_v2_job_result_claims AS prerequisite_claim
                ON prerequisite_claim.logical_job_id =
                    dependency.prerequisite_job_id
               AND prerequisite_claim.state = 'finalized'
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
                AND (prerequisite.logical_job_id IS NULL
                     OR prerequisite_claim.logical_job_id IS NULL
                     OR NEW.claimed_at_ms < prerequisite.finalized_at_ms)
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 job-result claim is not exactly ready'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_job_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_result_claims AS claim
        JOIN workflow_plan_v2_jobs AS job
          ON job.id = claim.logical_job_id
         AND job.run_id = claim.run_id
         AND job.invocation_id = claim.invocation_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.invocation_id = job.invocation_id
         AND publication.logical_job_id = job.id
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.finalized_at_ms >= claim.claimed_at_ms
          AND NEW.finalized_at_ms < claim.expires_at_ms
          AND job.logical_key = NEW.logical_key
          AND job.source_order = NEW.source_order
          AND job.execution_kind = 'steps'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_digest = NEW.plan_digest
          AND invocation.plan_object_key = NEW.plan_object_key
          AND invocation.plan_size_bytes = NEW.plan_size_bytes
          AND invocation.plan_media_type = NEW.plan_media_type
          AND invocation.plan_schema = NEW.plan_schema
          AND publication.activation_output_digest = NEW.activation_output_digest
          AND publication.condition_matched = NEW.condition_matched
          AND publication.instance_count = NEW.instance_count
    ) AND NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_result_claims AS claim
        JOIN workflow_plan_v2_jobs AS job
          ON job.id = claim.logical_job_id
         AND job.run_id = claim.run_id
         AND job.invocation_id = claim.invocation_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_reusable_call_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.parent_invocation_id = job.invocation_id
         AND publication.caller_logical_job_id = job.id
        JOIN workflow_plan_v2_reusable_call_results AS call_result
          ON call_result.run_id = publication.run_id
         AND call_result.parent_invocation_id = publication.parent_invocation_id
         AND call_result.caller_logical_job_id = publication.caller_logical_job_id
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.finalized_at_ms >= claim.claimed_at_ms
          AND NEW.finalized_at_ms < claim.expires_at_ms
          AND job.logical_key = NEW.logical_key
          AND job.source_order = NEW.source_order
          AND job.execution_kind = 'reusable_workflow'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_digest = NEW.plan_digest
          AND invocation.plan_object_key = NEW.plan_object_key
          AND invocation.plan_size_bytes = NEW.plan_size_bytes
          AND invocation.plan_media_type = NEW.plan_media_type
          AND invocation.plan_schema = NEW.plan_schema
          AND publication.publication_digest = NEW.activation_output_digest
          AND publication.condition_matched = NEW.condition_matched
          AND NEW.instance_count = CASE WHEN publication.condition_matched
              THEN 1 ELSE 0 END
          AND call_result.sealed_at_ms IS NOT NULL
          AND call_result.parent_result_descriptor_digest = NEW.descriptor_digest
          AND call_result.parent_instances_digest = NEW.instances_digest
          AND call_result.parent_prerequisites_digest = NEW.prerequisites_digest
          AND call_result.parent_outputs_digest = NEW.outputs_digest
          AND call_result.parent_commit_digest = NEW.commit_digest
          AND call_result.effective_conclusion = NEW.effective_conclusion
          AND NEW.output_count = CASE WHEN publication.condition_matched
              THEN publication.output_mapping_count ELSE 0 END
          AND NEW.prerequisite_count = (
              SELECT count(*)
              FROM workflow_plan_v2_dependencies AS dependency
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 job result lacks exact plan/publication/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_job_result_instance()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_results AS logical_result
        JOIN workflow_plan_v2_job_result_claims AS logical_claim
          ON logical_claim.logical_job_id = logical_result.logical_job_id
        JOIN workflow_plan_v2_instance_results AS instance_result
          ON instance_result.logical_job_id = logical_result.logical_job_id
         AND instance_result.instance_id = NEW.instance_id
        JOIN workflow_plan_v2_instances AS instance
          ON instance.id = instance_result.instance_id
         AND instance.logical_job_id = instance_result.logical_job_id
        JOIN workflow_plan_v2_instance_result_claims AS instance_claim
          ON instance_claim.instance_id = instance_result.instance_id
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND logical_claim.state = 'aggregating'
          AND logical_result.claim_owner_id = logical_claim.owner_id
          AND logical_result.claim_generation = logical_claim.generation
          AND instance.matrix_index = NEW.matrix_index
          AND instance_result.terminal_ordinal = NEW.terminal_ordinal
          AND instance_result.descriptor_digest = NEW.instance_descriptor_digest
          AND instance_result.outputs_digest = NEW.instance_outputs_digest
          AND instance_result.commit_digest = NEW.instance_commit_digest
          AND instance_result.raw_conclusion = NEW.raw_conclusion
          AND instance_result.effective_conclusion = NEW.effective_conclusion
          AND instance_claim.state = 'finalized'
    ) AND NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_results AS logical_result
        JOIN workflow_plan_v2_job_result_claims AS logical_claim
          ON logical_claim.logical_job_id = logical_result.logical_job_id
        JOIN workflow_plan_v2_reusable_call_results AS call_result
          ON call_result.run_id = logical_result.run_id
         AND call_result.parent_invocation_id = logical_result.invocation_id
         AND call_result.caller_logical_job_id = logical_result.logical_job_id
        JOIN workflow_plan_v2_reusable_call_publications AS publication
          ON publication.run_id = call_result.run_id
         AND publication.parent_invocation_id = call_result.parent_invocation_id
         AND publication.caller_logical_job_id = call_result.caller_logical_job_id
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND logical_claim.state = 'aggregating'
          AND logical_result.claim_owner_id = logical_claim.owner_id
          AND logical_result.claim_generation = logical_claim.generation
          AND publication.condition_matched
          AND call_result.sealed_at_ms IS NOT NULL
          AND call_result.caller_instance_id = NEW.instance_id
          AND NEW.matrix_index = 0
          AND NEW.terminal_ordinal = 1
          AND call_result.descriptor_digest = NEW.instance_descriptor_digest
          AND call_result.outputs_digest = NEW.instance_outputs_digest
          AND call_result.commit_digest = NEW.instance_commit_digest
          AND call_result.effective_conclusion = NEW.raw_conclusion
          AND call_result.effective_conclusion = NEW.effective_conclusion
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 logical result instance evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_job_result_output()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_results AS logical_result
        JOIN workflow_plan_v2_job_result_claims AS claim
          ON claim.logical_job_id = logical_result.logical_job_id
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = logical_result.run_id
         AND job.invocation_id = logical_result.invocation_id
         AND job.id = logical_result.logical_job_id
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND claim.state = 'aggregating'
          AND logical_result.claim_owner_id = claim.owner_id
          AND logical_result.claim_generation = claim.generation
          AND logical_result.claim_started_at_ms = claim.claimed_at_ms
          AND logical_result.claim_expires_at_ms = claim.expires_at_ms
          AND (
              job.execution_kind = 'steps'
              OR (
                  job.execution_kind = 'reusable_workflow'
                  AND EXISTS (
                      SELECT 1
                      FROM workflow_plan_v2_reusable_call_output_mappings AS mapping
                      JOIN workflow_plan_v2_reusable_call_results AS call_result
                        ON call_result.run_id = mapping.run_id
                       AND call_result.child_invocation_id =
                           mapping.child_invocation_id
                       AND call_result.parent_invocation_id = job.invocation_id
                       AND call_result.caller_logical_job_id = job.id
                       AND call_result.sealed_at_ms IS NOT NULL
                      JOIN workflow_plan_v2_reusable_call_result_outputs AS child_output
                        ON child_output.run_id = call_result.run_id
                       AND child_output.parent_invocation_id =
                           call_result.parent_invocation_id
                       AND child_output.caller_logical_job_id =
                           call_result.caller_logical_job_id
                       AND child_output.callee_output_name =
                           mapping.child_output_name
                      WHERE mapping.run_id = job.run_id
                        AND mapping.parent_output_name = NEW.output_name
                        AND mapping.sensitivity = NEW.sensitivity
                        AND NEW.public_value IS NOT DISTINCT FROM CASE
                            WHEN mapping.sensitivity = 'public'
                            THEN child_output.public_value
                            ELSE NULL
                        END
                  )
              )
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 logical output lacks exact result evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_guard_workflow_plan_v2_invocation_run_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.invocation_kind = 'reusable'
       AND OLD.state = 'active'
       AND NEW.state IN ('completed', 'cancelled', 'failed')
       AND NEW.revision = OLD.revision + 1
       AND NEW.updated_at_ms >= OLD.updated_at_ms
       AND EXISTS (
           SELECT 1
           FROM workflow_plan_v2_reusable_call_results AS call_result
           JOIN workflow_plan_v2_reusable_call_publications AS publication
             ON publication.run_id = call_result.run_id
            AND publication.parent_invocation_id =
                call_result.parent_invocation_id
            AND publication.caller_logical_job_id =
                call_result.caller_logical_job_id
           WHERE call_result.run_id = NEW.run_id
             AND call_result.child_invocation_id = NEW.id
             AND call_result.sealed_at_ms IS NOT NULL
             AND publication.condition_matched
             AND call_result.completed_at_ms = NEW.updated_at_ms
             AND NEW.state = CASE call_result.effective_conclusion
                 WHEN 'success' THEN 'completed'
                 WHEN 'skipped' THEN 'completed'
                 WHEN 'cancelled' THEN 'cancelled'
                 ELSE 'failed'
             END
       )
    THEN
        RETURN NEW;
    END IF;

    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state = 'cancelled'
       AND OLD.state IN ('pending', 'active')
       AND NEW.revision = OLD.revision + 1
       AND NEW.updated_at_ms >= OLD.updated_at_ms
       AND EXISTS (
           SELECT 1
           FROM workflow_plan_v2_concurrency_cancellations AS cancellation
           WHERE cancellation.run_id = NEW.run_id
             AND cancellation.root_invocation_id = NEW.id
             AND cancellation.prior_invocation_state = OLD.state
             AND cancellation.prior_invocation_revision = OLD.revision
             AND cancellation.prior_invocation_updated_at_ms = OLD.updated_at_ms
             AND cancellation.cancelled_at_ms = NEW.updated_at_ms
       )
    THEN
        RETURN NEW;
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state IN ('completed', 'cancelled', 'failed') THEN
        IF OLD.state NOT IN ('pending', 'active')
           OR NEW.revision <> OLD.revision + 1
           OR NEW.updated_at_ms < OLD.updated_at_ms
           OR NOT EXISTS (
               SELECT 1
               FROM workflow_plan_v2_run_results AS run_result
               JOIN workflow_plan_v2_run_result_claims AS claim
                 ON claim.run_id = run_result.run_id
               WHERE run_result.run_id = NEW.run_id
                 AND run_result.root_invocation_id = NEW.id
                 AND claim.state = 'aggregating'
                 AND run_result.invocation_state = OLD.state
                 AND run_result.invocation_revision = OLD.revision
                 AND run_result.invocation_updated_at_ms = OLD.updated_at_ms
                 AND run_result.finalized_at_ms = NEW.updated_at_ms
                 AND NEW.state = CASE run_result.effective_conclusion
                     WHEN 'success' THEN 'completed'
                     WHEN 'skipped' THEN 'completed'
                     WHEN 'cancelled' THEN 'cancelled'
                     ELSE 'failed'
                 END
           )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 invocation terminal transition lacks result evidence'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state IN ('completed', 'cancelled', 'failed')
          AND (NEW.state IS DISTINCT FROM OLD.state
               OR NEW.revision IS DISTINCT FROM OLD.revision
               OR NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal invocation is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_reject_reusable_runtime_evidence_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'reusable workflow runtime evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'workflow_plan_v2_reusable_runtime_immutable';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_reusable_call_mappings_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_call_output_mappings
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_output_contracts_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_call_output_contracts
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_call_results_reject_delete
BEFORE DELETE ON workflow_plan_v2_reusable_call_results
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_result_jobs_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_call_result_jobs
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_result_outputs_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_call_result_outputs
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_calls_reject_delete
BEFORE DELETE ON workflow_plan_v2_reusable_call_publications
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_call_mappings_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_call_output_mappings
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_output_contracts_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_call_output_contracts
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_call_results_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_call_results
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_result_jobs_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_call_result_jobs
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_result_outputs_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_call_result_outputs
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_calls_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_call_publications
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_runtime_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_reusable_contracts_freeze_for_run_result
BEFORE INSERT OR DELETE ON workflow_plan_v2_reusable_call_output_contracts
FOR EACH ROW EXECUTE FUNCTION automata_freeze_workflow_plan_v2_run_graph();
CREATE TRIGGER workflow_plan_v2_reusable_mappings_freeze_for_run_result
BEFORE INSERT OR DELETE ON workflow_plan_v2_reusable_call_output_mappings
FOR EACH ROW EXECUTE FUNCTION automata_freeze_workflow_plan_v2_run_graph();
CREATE TRIGGER workflow_plan_v2_reusable_calls_freeze_for_run_result
BEFORE INSERT OR DELETE ON workflow_plan_v2_reusable_call_publications
FOR EACH ROW EXECUTE FUNCTION automata_freeze_workflow_plan_v2_run_graph();
CREATE TRIGGER workflow_plan_v2_reusable_results_freeze_for_run_result
BEFORE INSERT OR DELETE ON workflow_plan_v2_reusable_call_results
FOR EACH ROW EXECUTE FUNCTION automata_freeze_workflow_plan_v2_run_graph();
CREATE TRIGGER workflow_plan_v2_reusable_result_jobs_freeze_for_run_result
BEFORE INSERT OR DELETE ON workflow_plan_v2_reusable_call_result_jobs
FOR EACH ROW EXECUTE FUNCTION automata_freeze_workflow_plan_v2_run_graph();
CREATE TRIGGER workflow_plan_v2_reusable_result_outputs_freeze_for_run_result
BEFORE INSERT OR DELETE ON workflow_plan_v2_reusable_call_result_outputs
FOR EACH ROW EXECUTE FUNCTION automata_freeze_workflow_plan_v2_run_graph();
