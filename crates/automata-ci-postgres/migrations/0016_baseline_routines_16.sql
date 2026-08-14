-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_validate_workflow_run_public_rerun_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    candidate workflow_runs%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'workflow_runs' THEN
        candidate := NEW;
    ELSE
        SELECT * INTO candidate FROM workflow_runs WHERE id = NEW.run_id;
    END IF;
    IF candidate.id IS NULL THEN
        RAISE EXCEPTION 'workflow rerun public identity has no physical run'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_run_public_rerun_identity_exact';
    ELSIF candidate.public_run_id_alias = candidate.run_id_alias THEN
        IF EXISTS (
            SELECT 1 FROM workflow_rerun_attempts AS attempt
            WHERE attempt.run_id = candidate.id
              AND attempt.source_run_id IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'workflow run root public identity is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'workflow_run_public_rerun_identity_exact';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_runs AS root ON root.id = attempt.root_run_id
        WHERE attempt.run_id = candidate.id
          AND attempt.source_run_id IS NOT NULL
          AND attempt.attempt = candidate.run_attempt
          AND root.run_attempt = 1
          AND root.run_id_alias = root.public_run_id_alias
          AND root.public_run_id_alias = candidate.public_run_id_alias
          AND root.workflow_id = candidate.workflow_id
          AND root.run_number = candidate.run_number
    ) THEN
        RAISE EXCEPTION 'workflow run public identity lacks exact rerun lineage'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_run_public_rerun_identity_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_workflow_runtime_policy_propagation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    expected_revision BIGINT;
    expected_digest BYTEA;
    upstream_exact BOOLEAN := FALSE;
BEGIN
    SELECT policy_revision, policy_digest
      INTO expected_revision, expected_digest
    FROM logical_workflow_runtime_policy_pins AS pin
    WHERE run_id = NEW.run_id
    FOR KEY SHARE OF pin;
    IF NOT FOUND
        OR NEW.runtime_policy_revision IS DISTINCT FROM expected_revision
        OR NEW.runtime_policy_digest IS DISTINCT FROM expected_digest
    THEN
        RAISE EXCEPTION 'logical workflow row lacks its exact runtime policy pin'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_propagation_exact';
    END IF;

    -- The run pin is necessary but not sufficient: lock and compare the exact
    -- immediate historical chain so no direct SQL writer can splice two rows
    -- which happen to name the same run. No current pointer participates.
    IF TG_TABLE_NAME = 'logical_workflow_activation_preparation_claims' THEN
        SELECT (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM logical_workflow_jobs AS job
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
        FOR KEY SHARE OF job;
    ELSIF TG_TABLE_NAME = 'logical_workflow_activation_preparations' THEN
        SELECT (claim.runtime_policy_revision, claim.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM logical_workflow_activation_preparation_claims AS claim
        JOIN logical_workflow_jobs AS job
          ON job.run_id = claim.run_id
         AND job.invocation_id = claim.invocation_id
         AND job.id = claim.logical_job_id
        WHERE claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF claim, job;
    ELSIF TG_TABLE_NAME = 'logical_workflow_activation_publications' THEN
        SELECT (preparation.runtime_policy_revision,
                preparation.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM logical_workflow_activation_preparations AS preparation
        JOIN logical_workflow_jobs AS job
          ON job.run_id = preparation.run_id
         AND job.invocation_id = preparation.invocation_id
         AND job.id = preparation.logical_job_id
        WHERE preparation.run_id = NEW.run_id
          AND preparation.invocation_id = NEW.invocation_id
          AND preparation.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF preparation, job;
    ELSIF TG_TABLE_NAME = 'logical_workflow_instances' THEN
        SELECT (publication.runtime_policy_revision,
                publication.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM logical_workflow_activation_publications AS publication
        JOIN logical_workflow_jobs AS job
          ON job.run_id = publication.run_id
         AND job.invocation_id = publication.invocation_id
         AND job.id = publication.logical_job_id
        WHERE publication.run_id = NEW.run_id
          AND publication.invocation_id = NEW.invocation_id
          AND publication.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF publication, job;
    ELSIF TG_TABLE_NAME = 'logical_workflow_materialization_claims' THEN
        SELECT (instance.runtime_policy_revision, instance.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (publication.runtime_policy_revision,
                    publication.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM logical_workflow_instances AS instance
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN logical_workflow_jobs AS job
          ON job.run_id = instance.run_id
         AND job.invocation_id = instance.invocation_id
         AND job.id = instance.logical_job_id
        WHERE instance.id = NEW.instance_id
          AND instance.run_id = NEW.run_id
          AND instance.invocation_id = NEW.invocation_id
          AND instance.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF instance, publication, job;
    ELSIF TG_TABLE_NAME = 'logical_workflow_concrete_jobs' THEN
        SELECT (claim.runtime_policy_revision, claim.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (instance.runtime_policy_revision, instance.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (publication.runtime_policy_revision,
                    publication.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM logical_workflow_materialization_claims AS claim
        JOIN logical_workflow_instances AS instance
          ON instance.id = claim.instance_id
         AND instance.run_id = claim.run_id
         AND instance.invocation_id = claim.invocation_id
         AND instance.logical_job_id = claim.logical_job_id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN logical_workflow_jobs AS job
          ON job.run_id = instance.run_id
         AND job.invocation_id = instance.invocation_id
         AND job.id = instance.logical_job_id
        WHERE claim.instance_id = NEW.instance_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF claim, instance, publication, job;
    ELSE
        RAISE EXCEPTION 'runtime policy propagation trigger is attached to an unknown table'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_propagation_table';
    END IF;

    IF upstream_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'logical workflow runtime policy differs from its locked upstream chain'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_upstream_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_verify_provider_delivery_workflow_inventory() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    inventory provider_delivery_workflow_inventories%ROWTYPE;
    entry_count INTEGER;
BEGIN
    SELECT * INTO inventory
    FROM provider_delivery_workflow_inventories
    WHERE inbox_id = NEW.inbox_id;
    SELECT count(*) INTO entry_count
    FROM provider_delivery_workflow_inventory_entries
    WHERE inbox_id = NEW.inbox_id;
    IF inventory.inbox_id IS NULL
        OR inventory.workflow_count <> entry_count
        OR inventory.inventory_digest <>
            automata_provider_delivery_workflow_inventory_digest(NEW.inbox_id)
    THEN
        RAISE EXCEPTION 'provider delivery workflow inventory digest is not canonical'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_inventory_digest_canonical';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_wake_github_check_projection() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.desired_revision <> OLD.desired_revision THEN
        UPDATE github_check_projection_outbox
        SET state = 'pending',
            next_attempt_at_ms = NULL,
            last_failure_kind = NULL,
            blocked_reason = NULL,
            state_updated_at_ms = NEW.desired_updated_at_ms
        WHERE subject_id = NEW.id
          AND state IN ('pending', 'retry', 'delivered');
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_project_job_attempt_to_github_check() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    target_state TEXT;
    target_conclusion TEXT;
    target_cause TEXT;
    projected_count BIGINT;
BEGIN
    IF NEW.lifecycle IS NOT DISTINCT FROM OLD.lifecycle THEN
        RETURN NULL;
    END IF;

    CASE NEW.lifecycle
        WHEN 'leased', 'preparing', 'running', 'cancelling', 'finalizing' THEN
            target_state := 'in_progress';
        WHEN 'succeeded' THEN
            target_state := 'completed';
            target_conclusion := 'success';
            target_cause := 'workflow_success';
        WHEN 'failed', 'lost' THEN
            target_state := 'completed';
            target_conclusion := 'failure';
            target_cause := 'workflow_failure';
        WHEN 'cancelled' THEN
            target_state := 'completed';
            target_conclusion := 'cancelled';
            target_cause := 'workflow_cancelled';
        WHEN 'timed_out' THEN
            target_state := 'completed';
            target_conclusion := 'timed_out';
            target_cause := 'workflow_timed_out';
        WHEN 'skipped' THEN
            target_state := 'completed';
            target_conclusion := 'skipped';
            target_cause := 'workflow_skipped';
        ELSE
            RETURN NULL;
    END CASE;

    UPDATE github_check_subjects AS subject
    SET desired_state = target_state,
        desired_conclusion = target_conclusion,
        terminal_cause = target_cause,
        desired_revision = subject.desired_revision + 1,
        desired_updated_at_ms = NEW.changed_at_ms
    WHERE subject.job_attempt_id = NEW.id
      AND subject.job_id = NEW.job_id
      AND subject.subject_kind = 'job'
      AND (
          target_state = 'in_progress'
          AND subject.desired_state = 'queued'
          OR target_state = 'completed'
          AND subject.desired_state IN ('queued', 'in_progress')
      );
    GET DIAGNOSTICS projected_count = ROW_COUNT;

    IF EXISTS (
        SELECT 1
        FROM github_check_subjects
        WHERE job_attempt_id = NEW.id
          AND subject_kind = 'job'
    ) AND projected_count <> 1 AND NOT EXISTS (
        SELECT 1
        FROM github_check_subjects
        WHERE job_attempt_id = NEW.id
          AND job_id = NEW.job_id
          AND subject_kind = 'job'
          AND desired_state = target_state
          AND desired_conclusion IS NOT DISTINCT FROM target_conclusion
          AND terminal_cause IS NOT DISTINCT FROM target_cause
    ) THEN
        RAISE EXCEPTION 'GitHub job Check lifecycle did not advance exactly'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_job_lifecycle_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_workflow_admission_github_evidence_flag_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.github_subject_evidence_required IS DISTINCT FROM
        OLD.github_subject_evidence_required
    THEN
        RAISE EXCEPTION 'workflow admission GitHub evidence expectation is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_admission_github_evidence_flag_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_logical_workflow_invocation_published(target_run_id uuid, target_invocation_id uuid) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT EXISTS (
        SELECT 1
        FROM logical_workflow_runs AS marker
        WHERE marker.run_id = target_run_id
          AND (
              marker.root_invocation_id = target_invocation_id
              OR EXISTS (
                  SELECT 1
                  FROM logical_workflow_reusable_call_publications AS publication
                  JOIN workflow_runs AS run
                    ON run.id = publication.run_id
                  JOIN repositories AS repository
                    ON repository.id = run.repository_id
                   AND repository.tenant_id = publication.tenant_id
                   AND repository.id = publication.repository_id
                  JOIN logical_workflow_reusable_invocation_expansions AS planned
                    ON planned.run_id = publication.run_id
                   AND planned.parent_invocation_id = publication.parent_invocation_id
                   AND planned.caller_logical_job_id = publication.caller_logical_job_id
                   AND planned.invocation_id = publication.child_invocation_id
                  JOIN logical_workflow_reusable_workflow_catalog AS catalog
                    ON catalog.run_id = planned.run_id
                   AND catalog.catalog_entry_id = planned.catalog_entry_id
                  JOIN logical_workflow_invocations AS child
                    ON child.run_id = planned.run_id
                   AND child.id = planned.invocation_id
                  JOIN logical_workflow_jobs AS caller
                    ON caller.run_id = planned.run_id
                   AND caller.invocation_id = planned.parent_invocation_id
                   AND caller.id = planned.caller_logical_job_id
                  JOIN logical_workflow_reusable_permission_snapshots AS permissions
                    ON permissions.run_id = planned.run_id
                   AND permissions.invocation_id = planned.invocation_id
                   AND permissions.permission_digest = publication.permission_digest
                  JOIN logical_workflow_reusable_call_output_contracts AS output_contract
                    ON output_contract.run_id = publication.run_id
                   AND output_contract.child_invocation_id = publication.child_invocation_id
                   AND output_contract.mapping_count = publication.output_mapping_count
                   AND output_contract.mapping_digest = publication.output_mapping_digest
                  JOIN logical_workflow_runtime_policy_pins AS pin
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
                         FROM logical_workflow_jobs AS active
                         WHERE active.run_id = planned.run_id
                           AND active.invocation_id = planned.invocation_id)
                        = (SELECT count(*)
                           FROM logical_workflow_reusable_expanded_jobs AS expected
                           WHERE expected.run_id = planned.run_id
                             AND expected.invocation_id = planned.invocation_id)
                    AND NOT EXISTS (
                        SELECT 1
                        FROM logical_workflow_reusable_expanded_jobs AS expected
                        LEFT JOIN logical_workflow_jobs AS active
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
                         FROM logical_workflow_dependencies AS active
                         WHERE active.run_id = planned.run_id
                           AND active.invocation_id = planned.invocation_id)
                        = (SELECT count(*)
                           FROM logical_workflow_reusable_expanded_dependencies AS expected
                           WHERE expected.run_id = planned.run_id
                             AND expected.invocation_id = planned.invocation_id)
                    AND NOT EXISTS (
                        SELECT 1
                        FROM logical_workflow_reusable_expanded_dependencies AS expected
                        LEFT JOIN logical_workflow_dependencies AS active
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
$$;

CREATE FUNCTION automata_workflow_rerun_check_requires_atomic_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    durable github_check_subjects%ROWTYPE;
    evidence workflow_rerun_check_evidence%ROWTYPE;
    run_evidence github_workflow_rerun_subject_evidence%ROWTYPE;
    outbox github_check_projection_outbox%ROWTYPE;
BEGIN
    IF NEW.origin_kind <> 'workflow_rerun' OR NEW.subject_kind = 'job' THEN
        RETURN NULL;
    END IF;
    SELECT * INTO durable
    FROM github_check_subjects
    WHERE id = NEW.id;
    SELECT * INTO evidence
    FROM workflow_rerun_check_evidence
    WHERE run_id = NEW.workflow_rerun_run_id
      AND github_check_subject_id = NEW.id;
    SELECT * INTO run_evidence
    FROM github_workflow_rerun_subject_evidence
    WHERE tenant_id = NEW.tenant_id
      AND run_id = NEW.workflow_rerun_run_id
      AND github_check_subject_id = NEW.id;
    SELECT * INTO outbox
    FROM github_check_projection_outbox
    WHERE subject_id = NEW.id;
    IF durable.id IS NULL
        OR durable.workflow_run_id <> NEW.workflow_rerun_run_id
        OR durable.linked_at_ms <> durable.created_at_ms
        OR durable.desired_state <> 'in_progress'
        OR durable.desired_conclusion IS NOT NULL
        OR durable.terminal_cause IS NOT NULL
        OR durable.desired_revision <> 2
        OR durable.desired_updated_at_ms <> durable.created_at_ms
        OR evidence.run_id IS NULL
        OR evidence.recorded_at_ms <> durable.created_at_ms
        OR run_evidence.run_id IS NULL
        OR run_evidence.github_check_head_sha <> durable.head_sha
        OR run_evidence.admitted_at_ms <> durable.created_at_ms
        OR octet_length(run_evidence.subject_evidence_sha256) <> 32
        OR outbox.subject_id IS NULL
        OR outbox.state <> 'pending'
        OR outbox.attempted_revision IS NOT NULL
        OR outbox.attempt_count <> 0
        OR outbox.claim_fence <> 0
        OR outbox.projected_revision <> 0
        OR outbox.state_updated_at_ms <> durable.created_at_ms
    THEN
        RAISE EXCEPTION 'workflow rerun Check requires atomic evidence and outbox'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_check_atomic_evidence_required';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_workflow_rerun_link_requires_run_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    evidence github_workflow_rerun_subject_evidence%ROWTYPE;
BEGIN
    IF NEW.subject_kind = 'job'
        OR NEW.origin_kind <> 'workflow_rerun'
        OR OLD.workflow_run_id IS NOT NULL
        OR NEW.workflow_run_id IS NULL
    THEN
        RETURN NULL;
    END IF;
    SELECT * INTO evidence
    FROM github_workflow_rerun_subject_evidence
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND run_id = NEW.workflow_run_id
      AND github_check_subject_id = NEW.id;
    IF evidence.run_id IS NULL
        OR NEW.workflow_run_id <> NEW.workflow_rerun_run_id
        OR NEW.linked_at_ms <> evidence.admitted_at_ms
        OR NEW.desired_state <> 'in_progress'
        OR NEW.desired_conclusion IS NOT NULL
        OR NEW.terminal_cause IS NOT NULL
        OR NEW.desired_revision <> 2
        OR NEW.desired_updated_at_ms <> evidence.admitted_at_ms
        OR NEW.head_sha <> evidence.github_check_head_sha
    THEN
        RAISE EXCEPTION 'workflow rerun Check link requires exact run evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_check_link_evidence_required';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_workflow_rerun_now_ms() RETURNS bigint
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$
    SELECT floor(extract(epoch FROM transaction_timestamp()) * 1000)::BIGINT
$$;

CREATE FUNCTION automata_workflow_run_publication_snapshot_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.publication_policy_revision IS DISTINCT FROM OLD.publication_policy_revision
       OR NEW.requested_dashboard_visibility IS DISTINCT FROM OLD.requested_dashboard_visibility
       OR NEW.effective_dashboard_visibility IS DISTINCT FROM OLD.effective_dashboard_visibility
       OR NEW.requested_log_visibility IS DISTINCT FROM OLD.requested_log_visibility
       OR NEW.requested_artifact_visibility IS DISTINCT FROM OLD.requested_artifact_visibility
       OR NEW.publication_safety_reason IS DISTINCT FROM OLD.publication_safety_reason
       OR NEW.publication_safety_schema IS DISTINCT FROM OLD.publication_safety_schema THEN
        RAISE EXCEPTION 'workflow run publication snapshots are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_runs_publication_snapshot_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_workflow_runtime_permission_policy_digest(bytea) RETURNS bytea
    LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
DECLARE
    document JSONB;
    permission_map JSONB;
    section_name TEXT;
    digest_label TEXT;
    section_index INTEGER := 0;
    entry_count BIGINT;
    map_canonical TEXT;
    canonical TEXT := '{';
    encoded BYTEA := pg_catalog.convert_to('permissions', 'UTF8')
        || pg_catalog.decode('00', 'hex');
    permission_entry RECORD;
BEGIN
    document := pg_catalog.convert_from($1, 'UTF8')::JSONB;
    IF pg_catalog.jsonb_typeof(document) <> 'object'
        OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(document)) <> 3
        OR NOT document ? 'provider_default'
        OR NOT document ? 'read_all'
        OR NOT document ? 'write_all'
    THEN
        RETURN NULL;
    END IF;

    FOR section_name, digest_label IN
        SELECT sections.section_name, sections.digest_label FROM (VALUES
            (1, 'provider_default', 'provider-default'),
            (2, 'read_all', 'read-all'),
            (3, 'write_all', 'write-all')
        ) AS sections(ordinal, section_name, digest_label)
        ORDER BY sections.ordinal
    LOOP
        permission_map := document->section_name;
        IF pg_catalog.jsonb_typeof(permission_map) <> 'object' THEN
            RETURN NULL;
        END IF;
        SELECT count(*) INTO entry_count
        FROM pg_catalog.jsonb_object_keys(permission_map);
        IF entry_count NOT BETWEEN 1 AND 64 THEN
            RETURN NULL;
        END IF;

        encoded := encoded
            || pg_catalog.convert_to(digest_label, 'UTF8')
            || pg_catalog.decode('00', 'hex')
            || pg_catalog.int8send(entry_count);
        FOR permission_entry IN
            SELECT key, value
            FROM pg_catalog.jsonb_each_text(permission_map)
            ORDER BY key COLLATE "C"
        LOOP
            IF pg_catalog.octet_length(permission_entry.key) NOT BETWEEN 1 AND 64
                OR permission_entry.key !~ '^[a-z]([a-z0-9]|-[a-z0-9])*$'
                OR permission_entry.value NOT IN ('read', 'write')
                OR (permission_entry.key = 'id-token' AND permission_entry.value = 'read')
                OR (section_name = 'read_all' AND permission_entry.value <> 'read')
            THEN
                RETURN NULL;
            END IF;
            encoded := encoded
                || automata_digest_part(
                    pg_catalog.convert_to(permission_entry.key, 'UTF8')
                )
                || CASE permission_entry.value
                    WHEN 'read' THEN pg_catalog.decode('01', 'hex')
                    WHEN 'write' THEN pg_catalog.decode('02', 'hex')
                   END;
        END LOOP;

        SELECT string_agg(
            pg_catalog.to_json(key)::TEXT || ':' || pg_catalog.to_json(value)::TEXT,
            ',' ORDER BY key COLLATE "C"
        ) INTO map_canonical
        FROM pg_catalog.jsonb_each_text(permission_map);
        IF section_index > 0 THEN
            canonical := canonical || ',';
        END IF;
        canonical := canonical || pg_catalog.to_json(section_name)::TEXT
            || ':{' || map_canonical || '}';
        section_index := section_index + 1;
    END LOOP;
    canonical := canonical || '}';

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_each_text(document->'read_all') AS read_permission
        WHERE NOT ((document->'write_all') ? (read_permission.key))
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_each_text(document->'write_all') AS write_permission
        WHERE write_permission.key <> 'id-token'
          AND NOT ((document->'read_all') ? (write_permission.key))
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_each_text(document->'provider_default') AS default_permission
        WHERE NOT ((document->'read_all') ? (default_permission.key))
           OR NOT ((document->'write_all') ? (default_permission.key))
           OR CASE default_permission.value WHEN 'read' THEN 1 WHEN 'write' THEN 2 END
              > CASE ((document->'write_all')->>(default_permission.key))
                    WHEN 'read' THEN 1 WHEN 'write' THEN 2 ELSE 0
                END
    ) OR pg_catalog.convert_to(canonical, 'UTF8') IS DISTINCT FROM $1 THEN
        RETURN NULL;
    END IF;
    RETURN encoded;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$_$;

CREATE FUNCTION automata_workflow_runtime_policy_canonical(text, uuid, bigint) RETURNS bytea
    LANGUAGE sql STABLE STRICT PARALLEL SAFE
    AS $_$
WITH header AS (
    SELECT policy_schema, workspace_root, workspace_derivation_version,
           mapping_count, permission_policy_canonical, resource_policy_canonical
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = $3
), mapping_parts AS (
    SELECT mapping.selector,
           '{"selector":' || pg_catalog.to_json(mapping.selector)::TEXT
           || ',"environment_profile":{"id":'
           || pg_catalog.to_json(mapping.environment_profile_id)::TEXT
           || ',"manifest_sha256":"'
           || pg_catalog.encode(mapping.environment_profile_digest, 'hex')
           || '"},"operating_system":'
           || pg_catalog.to_json(mapping.operating_system)::TEXT
           || ',"architecture":'
           || pg_catalog.to_json(mapping.architecture)::TEXT
           || ',"container_features":['
           || COALESCE(
                string_agg(
                    pg_catalog.to_json(feature.feature)::TEXT,
                    ',' ORDER BY feature.feature
                ),
                ''
              )
           || ']}' AS encoded,
           count(feature.feature)::INTEGER AS actual_feature_count,
           mapping.feature_count
    FROM workflow_runtime_policy_mappings AS mapping
    LEFT JOIN workflow_runtime_policy_features AS feature
      ON feature.tenant_id = mapping.tenant_id
     AND feature.repository_id = mapping.repository_id
     AND feature.policy_revision = mapping.policy_revision
     AND feature.selector = mapping.selector
    WHERE mapping.tenant_id = $1
      AND mapping.repository_id = $2
      AND mapping.policy_revision = $3
    GROUP BY mapping.selector, mapping.environment_profile_id,
             mapping.environment_profile_digest, mapping.operating_system,
             mapping.architecture, mapping.feature_count
), catalog AS (
    SELECT count(*)::INTEGER AS actual_mapping_count,
           bool_and(actual_feature_count = feature_count) AS features_exact,
           COALESCE(string_agg(encoded, ',' ORDER BY selector), '') AS encoded
    FROM mapping_parts
)
SELECT pg_catalog.convert_to(
    '{"schema":1,"workspace":{"schema":1,"root":"/__w","derivation":1},"mappings":['
    || catalog.encoded || '],"permissions":'
    || pg_catalog.convert_from(header.permission_policy_canonical, 'UTF8')
    || ',"resources":'
    || pg_catalog.convert_from(header.resource_policy_canonical, 'UTF8')
    || '}',
    'UTF8'
)
FROM header CROSS JOIN catalog
WHERE header.policy_schema = 1
  AND header.workspace_root = '/__w'
  AND header.workspace_derivation_version = 1
  AND automata_workflow_runtime_permission_policy_digest(
      header.permission_policy_canonical
  ) IS NOT NULL
  AND header.mapping_count = catalog.actual_mapping_count
  AND catalog.features_exact IS TRUE
$_$;

CREATE FUNCTION automata_workflow_runtime_policy_digest(text, uuid, bigint) RETURNS bytea
    LANGUAGE sql STABLE STRICT PARALLEL SAFE
    AS $_$
WITH header AS (
    SELECT policy_schema, workspace_root, workspace_derivation_version,
           mapping_count, permission_policy_canonical, resource_policy_canonical
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = $3
), mapping_parts AS (
    SELECT mapping.selector,
           automata_digest_part(
               pg_catalog.convert_to(mapping.selector, 'UTF8')
           )
           || automata_digest_part(
               pg_catalog.convert_to(mapping.environment_profile_id, 'UTF8')
           )
           || mapping.environment_profile_digest
           || CASE mapping.operating_system
                WHEN 'linux' THEN pg_catalog.decode('01', 'hex')
                WHEN 'windows' THEN pg_catalog.decode('02', 'hex')
                WHEN 'macos' THEN pg_catalog.decode('03', 'hex')
              END
           || CASE mapping.architecture
                WHEN 'x86_64' THEN pg_catalog.decode('01', 'hex')
                WHEN 'aarch64' THEN pg_catalog.decode('02', 'hex')
              END
           || pg_catalog.int8send(count(feature.feature)::BIGINT)
           || COALESCE(
                string_agg(
                    automata_digest_part(
                        pg_catalog.convert_to(feature.feature, 'UTF8')
                    ),
                    pg_catalog.decode('', 'hex') ORDER BY feature.feature
                ),
                pg_catalog.decode('', 'hex')
              ) AS encoded,
           count(feature.feature)::INTEGER AS actual_feature_count,
           mapping.feature_count
    FROM workflow_runtime_policy_mappings AS mapping
    LEFT JOIN workflow_runtime_policy_features AS feature
      ON feature.tenant_id = mapping.tenant_id
     AND feature.repository_id = mapping.repository_id
     AND feature.policy_revision = mapping.policy_revision
     AND feature.selector = mapping.selector
    WHERE mapping.tenant_id = $1
      AND mapping.repository_id = $2
      AND mapping.policy_revision = $3
    GROUP BY mapping.selector, mapping.environment_profile_id,
             mapping.environment_profile_digest, mapping.operating_system,
             mapping.architecture, mapping.feature_count
), catalog AS (
    SELECT count(*)::INTEGER AS actual_mapping_count,
           bool_and(actual_feature_count = feature_count) AS features_exact,
           COALESCE(
               string_agg(encoded, pg_catalog.decode('', 'hex') ORDER BY selector),
               pg_catalog.decode('', 'hex')
           ) AS encoded
    FROM mapping_parts
)
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.workflow-runtime-policy.v2', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || pg_catalog.int2send(header.policy_schema)
    || pg_catalog.int2send(header.workspace_derivation_version)
    || automata_digest_part(
        pg_catalog.convert_to(header.workspace_root, 'UTF8')
    )
    || pg_catalog.int8send(header.mapping_count::BIGINT)
    || catalog.encoded
    || automata_workflow_runtime_permission_policy_digest(
        header.permission_policy_canonical
    )
    || automata_workflow_runtime_resource_policy_digest(
        header.resource_policy_canonical
    )
)
FROM header CROSS JOIN catalog
WHERE header.policy_schema = 1
  AND automata_workflow_runtime_permission_policy_digest(
      header.permission_policy_canonical
  ) IS NOT NULL
  AND automata_workflow_runtime_resource_policy_digest(
      header.resource_policy_canonical
  ) IS NOT NULL
  AND header.mapping_count = catalog.actual_mapping_count
  AND catalog.features_exact IS TRUE
$_$;

CREATE FUNCTION automata_workflow_runtime_resource_policy_digest(bytea) RETURNS bytea
    LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
DECLARE
    document JSONB;
    capacity JSONB;
    encoded BYTEA := pg_catalog.convert_to('resources', 'UTF8')
        || pg_catalog.decode('00', 'hex');
    cpu NUMERIC;
    memory NUMERIC;
    ephemeral NUMERIC;
    gpu BIGINT;
    canonical TEXT;
BEGIN
    document := pg_catalog.convert_from($1, 'UTF8')::JSONB;
    IF pg_catalog.jsonb_typeof(document) <> 'object'
        OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(document)) <> 3
        OR pg_catalog.jsonb_typeof(document->'defaults') <> 'object'
        OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(document->'defaults')) <> 2
        OR pg_catalog.jsonb_typeof(document#>'{defaults,requests}') <> 'object'
        OR pg_catalog.jsonb_typeof(document#>'{defaults,limits}') <> 'object'
        OR pg_catalog.jsonb_typeof(document->'minimum_requests') <> 'object'
        OR pg_catalog.jsonb_typeof(document->'maximum_limits') <> 'object'
    THEN
        RETURN NULL;
    END IF;

    FOR capacity IN
        SELECT value
        FROM pg_catalog.jsonb_array_elements(pg_catalog.jsonb_build_array(
            document#>'{defaults,requests}',
            document#>'{defaults,limits}',
            document->'minimum_requests',
            document->'maximum_limits'
        ))
    LOOP
        IF (SELECT count(*) FROM pg_catalog.jsonb_object_keys(capacity)) <> 4 THEN
            RETURN NULL;
        END IF;
        IF pg_catalog.jsonb_typeof(capacity->'cpu_millis') <> 'number'
            OR pg_catalog.jsonb_typeof(capacity->'memory_bytes') <> 'number'
            OR pg_catalog.jsonb_typeof(capacity->'ephemeral_disk_bytes') <> 'number'
            OR pg_catalog.jsonb_typeof(capacity->'gpu_count') <> 'number'
            OR capacity->>'cpu_millis' !~ '^(0|[1-9][0-9]*)$'
            OR capacity->>'memory_bytes' !~ '^(0|[1-9][0-9]*)$'
            OR capacity->>'ephemeral_disk_bytes' !~ '^(0|[1-9][0-9]*)$'
            OR capacity->>'gpu_count' !~ '^(0|[1-9][0-9]*)$'
        THEN
            RETURN NULL;
        END IF;
        cpu := (capacity->>'cpu_millis')::NUMERIC;
        memory := (capacity->>'memory_bytes')::NUMERIC;
        ephemeral := (capacity->>'ephemeral_disk_bytes')::NUMERIC;
        gpu := (capacity->>'gpu_count')::BIGINT;
        IF cpu NOT BETWEEN 0 AND 4294967295
            OR memory NOT BETWEEN 0 AND 18446744073709551615
            OR ephemeral NOT BETWEEN 0 AND 18446744073709551615
            OR gpu NOT BETWEEN 0 AND 65535
        THEN
            RETURN NULL;
        END IF;
        encoded := encoded
            || pg_catalog.decode(
                pg_catalog.lpad(pg_catalog.to_hex(cpu::BIGINT), 8, '0'), 'hex'
            )
            || pg_catalog.decode(
                pg_catalog.lpad(
                    pg_catalog.to_hex(pg_catalog.trunc(memory / 4294967296)::BIGINT),
                    8, '0'
                )
                || pg_catalog.lpad(
                    pg_catalog.to_hex(pg_catalog.mod(memory, 4294967296)::BIGINT),
                    8, '0'
                ),
                'hex'
            )
            || pg_catalog.decode(
                pg_catalog.lpad(
                    pg_catalog.to_hex(pg_catalog.trunc(ephemeral / 4294967296)::BIGINT),
                    8, '0'
                )
                || pg_catalog.lpad(
                    pg_catalog.to_hex(pg_catalog.mod(ephemeral, 4294967296)::BIGINT),
                    8, '0'
                ),
                'hex'
            )
            || pg_catalog.decode(pg_catalog.lpad(pg_catalog.to_hex(gpu), 4, '0'), 'hex');
    END LOOP;

    IF (document#>>'{defaults,requests,cpu_millis}')::NUMERIC <= 0
        OR (document#>>'{defaults,requests,memory_bytes}')::NUMERIC <= 0
        OR (document#>>'{defaults,limits,cpu_millis}')::NUMERIC <= 0
        OR (document#>>'{defaults,limits,memory_bytes}')::NUMERIC <= 0
        OR (document#>>'{minimum_requests,cpu_millis}')::NUMERIC <= 0
        OR (document#>>'{minimum_requests,memory_bytes}')::NUMERIC <= 0
        OR (document#>>'{maximum_limits,cpu_millis}')::NUMERIC <= 0
        OR (document#>>'{maximum_limits,memory_bytes}')::NUMERIC <= 0
        OR (document#>>'{defaults,requests,cpu_millis}')::NUMERIC
            > (document#>>'{defaults,limits,cpu_millis}')::NUMERIC
        OR (document#>>'{defaults,requests,memory_bytes}')::NUMERIC
            > (document#>>'{defaults,limits,memory_bytes}')::NUMERIC
        OR (document#>>'{defaults,requests,ephemeral_disk_bytes}')::NUMERIC
            > (document#>>'{defaults,limits,ephemeral_disk_bytes}')::NUMERIC
        OR (document#>>'{defaults,requests,gpu_count}')::NUMERIC
            <> (document#>>'{defaults,limits,gpu_count}')::NUMERIC
        OR (document#>>'{minimum_requests,cpu_millis}')::NUMERIC
            > (document#>>'{defaults,requests,cpu_millis}')::NUMERIC
        OR (document#>>'{minimum_requests,memory_bytes}')::NUMERIC
            > (document#>>'{defaults,requests,memory_bytes}')::NUMERIC
        OR (document#>>'{minimum_requests,ephemeral_disk_bytes}')::NUMERIC
            > (document#>>'{defaults,requests,ephemeral_disk_bytes}')::NUMERIC
        OR (document#>>'{minimum_requests,gpu_count}')::NUMERIC
            > (document#>>'{defaults,requests,gpu_count}')::NUMERIC
        OR (document#>>'{defaults,limits,cpu_millis}')::NUMERIC
            > (document#>>'{maximum_limits,cpu_millis}')::NUMERIC
        OR (document#>>'{defaults,limits,memory_bytes}')::NUMERIC
            > (document#>>'{maximum_limits,memory_bytes}')::NUMERIC
        OR (document#>>'{defaults,limits,ephemeral_disk_bytes}')::NUMERIC
            > (document#>>'{maximum_limits,ephemeral_disk_bytes}')::NUMERIC
        OR (document#>>'{defaults,limits,gpu_count}')::NUMERIC
            > (document#>>'{maximum_limits,gpu_count}')::NUMERIC
    THEN
        RETURN NULL;
    END IF;
    canonical := '{"defaults":{"requests":{"cpu_millis":'
        || (document#>>'{defaults,requests,cpu_millis}')
        || ',"memory_bytes":' || (document#>>'{defaults,requests,memory_bytes}')
        || ',"ephemeral_disk_bytes":'
        || (document#>>'{defaults,requests,ephemeral_disk_bytes}')
        || ',"gpu_count":' || (document#>>'{defaults,requests,gpu_count}')
        || '},"limits":{"cpu_millis":'
        || (document#>>'{defaults,limits,cpu_millis}')
        || ',"memory_bytes":' || (document#>>'{defaults,limits,memory_bytes}')
        || ',"ephemeral_disk_bytes":'
        || (document#>>'{defaults,limits,ephemeral_disk_bytes}')
        || ',"gpu_count":' || (document#>>'{defaults,limits,gpu_count}')
        || '}},"minimum_requests":{"cpu_millis":'
        || (document#>>'{minimum_requests,cpu_millis}')
        || ',"memory_bytes":' || (document#>>'{minimum_requests,memory_bytes}')
        || ',"ephemeral_disk_bytes":'
        || (document#>>'{minimum_requests,ephemeral_disk_bytes}')
        || ',"gpu_count":' || (document#>>'{minimum_requests,gpu_count}')
        || '},"maximum_limits":{"cpu_millis":'
        || (document#>>'{maximum_limits,cpu_millis}')
        || ',"memory_bytes":' || (document#>>'{maximum_limits,memory_bytes}')
        || ',"ephemeral_disk_bytes":'
        || (document#>>'{maximum_limits,ephemeral_disk_bytes}')
        || ',"gpu_count":' || (document#>>'{maximum_limits,gpu_count}')
        || '}}';
    IF pg_catalog.convert_to(canonical, 'UTF8') IS DISTINCT FROM $1 THEN
        RETURN NULL;
    END IF;
    RETURN encoded;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$_$;

CREATE FUNCTION automata_workflow_variable_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.canonical_name IS DISTINCT FROM OLD.canonical_name
       OR NEW.created_by_principal_id IS DISTINCT FROM OLD.created_by_principal_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'workflow variable identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_variables_identity_immutable';
    END IF;
    IF NEW IS DISTINCT FROM OLD AND NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'workflow variable mutation requires one revision increment'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_variables_revision_guard';
    END IF;
    IF NEW.current_version_number IS DISTINCT FROM OLD.current_version_number
       AND NEW.current_version_number <> COALESCE(OLD.current_version_number, 0) + 1 THEN
        RAISE EXCEPTION 'workflow variable versions are monotonic'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_variables_version_guard';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_human_session_activation_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.session_kind = 'browser' THEN
            IF NEW.lifecycle_status <> 'active'
               OR NEW.activation_deadline_ms IS NOT NULL
               OR NEW.activated_at_ms IS NOT NULL THEN
                RAISE EXCEPTION 'browser sessions are immediately active'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.session_kind = 'cli' THEN
            IF NEW.lifecycle_status <> 'pending_activation'
               OR NEW.activation_deadline_ms IS NULL
               OR NEW.activated_at_ms IS NOT NULL THEN
                RAISE EXCEPTION 'new CLI sessions must await activation'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.session_kind IS DISTINCT FROM OLD.session_kind
       OR NEW.audience IS DISTINCT FROM OLD.audience
       OR NEW.issued_at_ms IS DISTINCT FROM OLD.issued_at_ms
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
       OR NEW.activation_deadline_ms IS DISTINCT FROM OLD.activation_deadline_ms THEN
        RAISE EXCEPTION 'session activation identity and deadline are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.lifecycle_status = 'pending_activation'
       AND NEW.lifecycle_status = 'active' THEN
        IF OLD.session_kind <> 'cli'
           OR OLD.audience <> 'automata.cli'
           OR OLD.activated_at_ms IS NOT NULL
           OR NEW.activated_at_ms IS NULL
           OR NEW.activated_at_ms < OLD.issued_at_ms
           OR NEW.activated_at_ms >= OLD.activation_deadline_ms
           OR NEW.revision <> OLD.revision + 1 THEN
            RAISE EXCEPTION 'invalid CLI session activation transition'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.lifecycle_status IS DISTINCT FROM OLD.lifecycle_status
       OR NEW.activated_at_ms IS DISTINCT FROM OLD.activated_at_ms THEN
        RAISE EXCEPTION 'session activation lifecycle is monotonic'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
