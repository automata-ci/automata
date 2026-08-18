-- Preserve the deployed migration lineage while moving Git object IDs from
-- hexadecimal text to their canonical algorithm-sized bytes. Historical
-- migrations are immutable: this upgrade is the only schema transition.

ALTER TABLE github_check_subjects
    DROP CONSTRAINT github_check_subjects_sha;
ALTER TABLE github_provider_delivery_evidence
    DROP CONSTRAINT github_provider_delivery_evidence_authenticated_event,
    DROP CONSTRAINT github_provider_delivery_evidence_digest_shape;
ALTER TABLE github_schedule_check_evidence
    DROP CONSTRAINT github_schedule_check_evidence_shape,
    DROP CONSTRAINT github_schedule_check_evidence_registry;
ALTER TABLE github_schedule_registry_revisions
    DROP CONSTRAINT github_schedule_registry_revisions_source_shape;
ALTER TABLE github_schedule_workflow_run_subject_evidence
    DROP CONSTRAINT github_schedule_workflow_run_subject_evidence_shape;
ALTER TABLE github_workflow_rerun_subject_evidence
    DROP CONSTRAINT github_workflow_rerun_subject_evidence_shape;
ALTER TABLE github_workflow_run_subject_evidence
    DROP CONSTRAINT github_workflow_run_subject_evidence_digest_shape;
ALTER TABLE workflow_rerun_check_evidence
    DROP CONSTRAINT workflow_rerun_check_evidence_shape;
ALTER TABLE provider_delivery_workflow_inventories
    DROP CONSTRAINT provider_delivery_workflow_inventories_shape;
ALTER TABLE logical_workflow_reusable_workflow_catalog
    DROP CONSTRAINT logical_workflow_reusable_catalog_revision_shape;
ALTER TABLE event_subject_selections
    DROP CONSTRAINT event_subject_selections_shape,
    DROP CONSTRAINT event_subject_selections_digest_canonical;

DROP VIEW github_workflow_run_manifest_origins;
DROP VIEW github_workflow_run_base_manifest_origins;

DROP FUNCTION automata_event_subject_selection_digest(
    smallint, smallint, bytea, uuid, text, uuid, smallint, uuid,
    text, text, text, bytea, bytea, bigint
);

ALTER TABLE github_schedule_check_evidence
    ALTER COLUMN source_revision TYPE bytea
    USING pg_catalog.decode(source_revision, 'hex');
ALTER TABLE github_schedule_registry_revisions
    ALTER COLUMN source_revision TYPE bytea
    USING pg_catalog.decode(source_revision, 'hex');
ALTER TABLE provider_delivery_workflow_inventories
    ALTER COLUMN source_revision TYPE bytea
    USING pg_catalog.decode(source_revision, 'hex');
ALTER TABLE logical_workflow_reusable_workflow_catalog
    ALTER COLUMN source_revision TYPE bytea
    USING pg_catalog.decode(source_revision, 'hex');
ALTER TABLE event_subject_selections
    ALTER COLUMN source_revision TYPE bytea
    USING pg_catalog.decode(source_revision, 'hex');

CREATE OR REPLACE FUNCTION automata_github_check_subject_insert_guard()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    schedule RECORD;
    rerun RECORD;
    job_check RECORD;
    now_ms BIGINT;
BEGIN
    IF NEW.desired_state <> 'queued'
        OR NEW.desired_revision <> 1
        OR NEW.desired_updated_at_ms <> NEW.created_at_ms
        OR NEW.workflow_run_id IS NOT NULL
        OR NEW.linked_at_ms IS NOT NULL
    THEN
        RAISE EXCEPTION 'GitHub Check subjects must begin queued and unlinked'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_initial_state';
    END IF;

    SELECT * INTO repository
    FROM repositories
    WHERE id = NEW.repository_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    IF repository.id IS NULL
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner || '/' || repository.name <>
            NEW.github_repository_name
    THEN
        RAISE EXCEPTION 'GitHub Check subject repository is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_authority_exact';
    END IF;

    IF NEW.subject_kind = 'job' THEN
        SELECT parent.id AS parent_id,
               parent.workflow_run_id AS parent_run_id,
               parent.tenant_id AS parent_tenant_id,
               parent.repository_id AS parent_repository_id,
               parent.provider_connection_id AS parent_connection_id,
               parent.provider_installation_id AS parent_installation_id,
               parent.github_repository_id AS parent_github_repository_id,
               parent.github_repository_name AS parent_repository_name,
               parent.github_app_id AS parent_app_id,
               parent.head_sha AS parent_head_sha,
               job.run_id AS job_run_id,
               attempt.job_id AS attempt_job_id,
               attempt.queued_at_ms
          INTO job_check
        FROM github_check_subjects AS parent
        JOIN jobs AS job ON job.id = NEW.job_id
        JOIN job_attempts AS attempt
          ON attempt.id = NEW.job_attempt_id
         AND attempt.job_id = job.id
        WHERE parent.id = NEW.parent_subject_id
          AND parent.subject_kind = 'workflow'
          AND parent.workflow_run_id = job.run_id
        FOR SHARE OF parent, job, attempt;
        IF NOT FOUND
            OR job_check.parent_run_id IS NULL
            OR job_check.parent_tenant_id <> NEW.tenant_id
            OR job_check.parent_repository_id <> NEW.repository_id
            OR job_check.parent_connection_id <> NEW.provider_connection_id
            OR job_check.parent_installation_id <> NEW.provider_installation_id
            OR job_check.parent_github_repository_id <> NEW.github_repository_id
            OR job_check.parent_repository_name <> NEW.github_repository_name
            OR job_check.parent_app_id <> NEW.github_app_id
            OR job_check.parent_head_sha <> NEW.head_sha
            OR NEW.created_at_ms <> job_check.queued_at_ms
            OR NEW.subject_key <>
                'job/' || NEW.job_id::TEXT || '/attempt/' || NEW.job_attempt_id::TEXT
        THEN
            RAISE EXCEPTION 'GitHub job Check authority is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_job_authority_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.origin_kind = 'provider_delivery' THEN
        SELECT * INTO delivery
        FROM provider_delivery_inbox
        WHERE id = NEW.provider_delivery_id
          AND tenant_id = NEW.tenant_id
        FOR SHARE;
        IF delivery.id IS NULL
            OR delivery.provider <> 'github'
            OR delivery.connection_id <> NEW.provider_connection_id
            OR delivery.installation_id <> NEW.provider_installation_id
            OR delivery.provider_repository_id <> NEW.github_repository_id
        THEN
            RAISE EXCEPTION 'GitHub Check delivery authority is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_authority_exact';
        END IF;
    ELSIF NEW.origin_kind = 'scheduled_fire' THEN
        now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
        SELECT fire.fire_id,
               fire.state AS fire_state,
               fire.claimed_at_ms,
               fire.claim_expires_at_ms,
               registry.source_revision,
               registry.default_branch_ref,
               entry.workflow_path,
               seal.registry_id AS sealed_registry_id,
               current.registry_id AS current_registry_id,
               manifest.provider_installation_id,
               manifest.github_repository_id,
               manifest.github_repository_name,
               manifest.github_app_id,
               manifest.check_name,
               manifest.git_ref
          INTO schedule
        FROM github_schedule_fires AS fire
        JOIN github_schedule_registry_revisions AS registry
          ON registry.tenant_id = fire.tenant_id
         AND registry.repository_id = fire.repository_id
         AND registry.provider_connection_id = fire.provider_connection_id
         AND registry.registry_id = fire.registry_id
        JOIN github_schedule_registry_entries AS entry
          ON entry.registry_id = fire.registry_id
         AND entry.ordinal = fire.entry_ordinal
        JOIN github_schedule_registry_seals AS seal
          ON seal.registry_id = registry.registry_id
         AND seal.inventory_digest = registry.inventory_digest
         AND seal.schedule_count = registry.schedule_count
        JOIN github_schedule_registry_current AS current
          ON current.tenant_id = registry.tenant_id
         AND current.repository_id = registry.repository_id
         AND current.provider_connection_id = registry.provider_connection_id
         AND current.registry_id = registry.registry_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = registry.tenant_id
         AND manifest.repository_id = registry.repository_id
         AND manifest.provider_connection_id = registry.provider_connection_id
         AND manifest.manifest_revision = registry.manifest_revision
         AND manifest.manifest_digest = registry.manifest_digest
        JOIN github_provider_manifest_current AS manifest_current
          ON manifest_current.tenant_id = manifest.tenant_id
         AND manifest_current.repository_id = manifest.repository_id
         AND manifest_current.provider_connection_id = manifest.provider_connection_id
         AND manifest_current.manifest_revision = manifest.manifest_revision
         AND manifest_current.manifest_digest = manifest.manifest_digest
        WHERE fire.fire_id = NEW.schedule_fire_id
          AND fire.tenant_id = NEW.tenant_id
          AND fire.repository_id = NEW.repository_id
          AND fire.provider_connection_id = NEW.provider_connection_id
        FOR SHARE OF fire, registry, entry, seal, current, manifest,
                     manifest_current;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'GitHub scheduled Check has no exact sealed fire'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_schedule_authority_exact';
        END IF;
        IF schedule.fire_state <> 'claimed'
            OR schedule.claimed_at_ms > now_ms
            OR schedule.claim_expires_at_ms <= now_ms
            OR NEW.created_at_ms < schedule.claimed_at_ms
            OR NEW.created_at_ms >= schedule.claim_expires_at_ms
            OR schedule.default_branch_ref <> schedule.git_ref
            OR NEW.subject_key <> schedule.workflow_path
            OR NEW.provider_installation_id <>
                schedule.provider_installation_id
            OR NEW.github_repository_id <> schedule.github_repository_id
            OR NEW.github_repository_name <> schedule.github_repository_name
            OR NEW.github_app_id <> schedule.github_app_id
            OR NEW.head_sha <> schedule.source_revision
            OR NEW.check_name <> schedule.check_name
        THEN
            RAISE EXCEPTION 'GitHub scheduled Check authority is not exact and live'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_schedule_authority_exact';
        END IF;
    ELSIF NEW.origin_kind = 'workflow_rerun' THEN
        SELECT attempt.run_id,
               attempt.source_run_id,
               attempt.created_at_ms,
               request.tenant_id,
               request.repository_id,
               request.committed_at_ms,
               run.head_sha AS run_head_sha,
               run.status AS run_status,
               source.id AS source_subject_id,
               source.tenant_id AS source_tenant_id,
               source.repository_id AS source_repository_id,
               source.subject_key AS source_subject_key,
               source.provider_connection_id AS source_connection_id,
               source.provider_installation_id AS source_installation_id,
               source.github_repository_id AS source_repository_provider_id,
               source.github_repository_name AS source_repository_name,
               source.github_app_id AS source_app_id,
               source.head_sha AS source_head_sha,
               source.check_name AS source_check_name,
               source.desired_state AS source_desired_state,
               source.desired_revision AS source_desired_revision
          INTO rerun
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.rerun_run_id = attempt.run_id
         AND request.source_run_id = attempt.source_run_id
        JOIN workflow_runs AS run ON run.id = attempt.run_id
        JOIN github_check_subjects AS source
          ON source.workflow_run_id = attempt.source_run_id
         AND source.subject_kind = 'workflow'
        WHERE attempt.run_id = NEW.workflow_rerun_run_id
          AND attempt.source_run_id IS NOT NULL
          AND 1 = (
              SELECT count(*)
              FROM github_check_subjects AS exact_source
              WHERE exact_source.workflow_run_id = attempt.source_run_id
                AND exact_source.subject_kind = 'workflow'
          )
        FOR SHARE OF attempt, request, run, source;
        IF NOT FOUND
            OR rerun.tenant_id <> NEW.tenant_id
            OR rerun.repository_id <> NEW.repository_id
            OR rerun.committed_at_ms <> rerun.created_at_ms
            OR rerun.run_status <> 'queued'
            OR rerun.run_head_sha <> NEW.head_sha
            OR rerun.source_tenant_id <> NEW.tenant_id
            OR rerun.source_repository_id <> NEW.repository_id
            OR rerun.source_desired_state <> 'completed'
            OR rerun.source_desired_revision <> 3
            OR NEW.created_at_ms <> rerun.created_at_ms
            OR NEW.subject_key <> rerun.source_subject_key
            OR NEW.provider_connection_id <> rerun.source_connection_id
            OR NEW.provider_installation_id <> rerun.source_installation_id
            OR NEW.github_repository_id <>
                rerun.source_repository_provider_id
            OR NEW.github_repository_name <> rerun.source_repository_name
            OR NEW.github_app_id <> rerun.source_app_id
            OR NEW.head_sha <> rerun.source_head_sha
            OR NEW.check_name <> rerun.source_check_name
        THEN
            RAISE EXCEPTION 'GitHub rerun Check authority is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_rerun_authority_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub Check subject origin is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_exact';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION automata_github_schedule_check_evidence_insert_guard()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
    exact BOOLEAN;
    now_ms BIGINT;
BEGIN
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT TRUE INTO exact
    FROM github_schedule_fires AS fire
    JOIN github_schedule_registry_revisions AS registry
      ON registry.tenant_id = fire.tenant_id
     AND registry.repository_id = fire.repository_id
     AND registry.provider_connection_id = fire.provider_connection_id
     AND registry.registry_id = fire.registry_id
    JOIN github_schedule_registry_entries AS entry
      ON entry.registry_id = fire.registry_id
     AND entry.ordinal = fire.entry_ordinal
    JOIN github_schedule_registry_seals AS seal
      ON seal.registry_id = registry.registry_id
     AND seal.inventory_digest = registry.inventory_digest
     AND seal.schedule_count = registry.schedule_count
    JOIN github_schedule_registry_current AS current
      ON current.tenant_id = registry.tenant_id
     AND current.repository_id = registry.repository_id
     AND current.provider_connection_id = registry.provider_connection_id
     AND current.registry_id = registry.registry_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = registry.tenant_id
     AND manifest.repository_id = registry.repository_id
     AND manifest.provider_connection_id = registry.provider_connection_id
     AND manifest.manifest_revision = registry.manifest_revision
     AND manifest.manifest_digest = registry.manifest_digest
    JOIN github_provider_manifest_current AS manifest_current
      ON manifest_current.tenant_id = manifest.tenant_id
     AND manifest_current.repository_id = manifest.repository_id
     AND manifest_current.provider_connection_id = manifest.provider_connection_id
     AND manifest_current.manifest_revision = manifest.manifest_revision
     AND manifest_current.manifest_digest = manifest.manifest_digest
    JOIN github_server_service_authorities AS authority
      ON authority.tenant_id = registry.tenant_id
     AND authority.id = NEW.checks_authority_id
    JOIN github_check_subjects AS subject
      ON subject.tenant_id = fire.tenant_id
     AND subject.repository_id = fire.repository_id
     AND subject.provider_connection_id = fire.provider_connection_id
     AND subject.schedule_fire_id = fire.fire_id
     AND subject.id = NEW.github_check_subject_id
    WHERE fire.fire_id = NEW.schedule_fire_id
      AND fire.tenant_id = NEW.tenant_id
      AND fire.repository_id = NEW.repository_id
      AND fire.provider_connection_id = NEW.provider_connection_id
      AND fire.registry_id = NEW.registry_id
      AND fire.entry_ordinal = NEW.entry_ordinal
      AND fire.scheduled_at_ms = NEW.scheduled_at_ms
      AND fire.state = 'claimed'
      AND fire.claimed_at_ms <= now_ms
      AND fire.claim_expires_at_ms > now_ms
      AND NEW.recorded_at_ms >= fire.claimed_at_ms
      AND NEW.recorded_at_ms < fire.claim_expires_at_ms
      AND registry.manifest_revision = NEW.provider_manifest_revision
      AND registry.manifest_digest = NEW.provider_manifest_digest
      AND registry.default_branch_ref = NEW.default_branch_ref
      AND registry.source_revision = NEW.source_revision
      AND registry.github_repository_owner_id = NEW.github_repository_owner_id
      AND registry.default_branch_ref = manifest.git_ref
      AND NEW.github_check_head_sha = registry.source_revision
      AND subject.origin_kind = 'scheduled_fire'
      AND subject.provider_delivery_id IS NULL
      AND subject.subject_key = entry.workflow_path
      AND subject.provider_installation_id = manifest.provider_installation_id
      AND subject.github_repository_id = manifest.github_repository_id
      AND subject.github_repository_name = manifest.github_repository_name
      AND subject.github_app_id = manifest.github_app_id
      AND subject.head_sha = NEW.github_check_head_sha
      AND subject.check_name = manifest.check_name
      AND subject.created_at_ms = NEW.recorded_at_ms
      AND authority.repository_id = registry.repository_id
      AND authority.provider_connection_id = registry.provider_connection_id
      AND authority.provider_installation_id = manifest.provider_installation_id
      AND authority.github_app_id = manifest.github_app_id
      AND authority.github_repository_id = manifest.github_repository_id
      AND authority.github_repository_name = manifest.github_repository_name
      AND authority.service_scope = 'checks_write'
      AND authority.github_app_client_id = manifest.github_app_client_id
      AND authority.github_app_jwt_issuer_kind = manifest.github_app_jwt_issuer_kind
      AND authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
      AND authority.app_configuration_revision =
          NEW.checks_authority_app_configuration_revision
      AND authority.app_configuration_revision = manifest.app_configuration_revision
      AND authority.policy_revision = NEW.checks_authority_policy_revision
      AND authority.policy_revision = manifest.policy_revision
      AND authority.identity_digest = NEW.checks_authority_identity_digest
      AND authority.state = 'active'
      AND authority.created_at_ms <= NEW.recorded_at_ms
    FOR SHARE OF fire, registry, entry, seal, current, manifest, manifest_current,
                 authority, subject;
    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'GitHub schedule Check evidence is not exact and live'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_check_evidence_authority_exact';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION automata_provider_delivery_workflow_inventory_digest(uuid)
 RETURNS bytea
 LANGUAGE sql
 STABLE PARALLEL SAFE STRICT
AS $function$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.provider-delivery-workflow-inventory.v1', 'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || inventory.manifest_digest
    || automata_digest_part(inventory.source_revision)
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
$function$;

CREATE OR REPLACE FUNCTION automata_validate_reusable_workflow_expansion()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
    expected_catalog_count BIGINT;
    expected_invocation_count BIGINT;
    expected_job_count BIGINT;
    expected_maximum_depth SMALLINT;
    expected_root_invocation_id UUID;
    durable_catalog_count BIGINT;
    durable_invocation_count BIGINT;
    durable_job_count BIGINT;
    durable_maximum_depth SMALLINT;
BEGIN
    SELECT catalog_entry_count,
           invocation_count,
           expanded_job_count,
           maximum_depth,
           root_invocation_id
      INTO expected_catalog_count,
           expected_invocation_count,
           expected_job_count,
           expected_maximum_depth,
           expected_root_invocation_id
    FROM logical_workflow_reusable_workflow_runs
    WHERE run_id = NEW.run_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable workflow expansion lacks its replay receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_receipt_required';
    END IF;

    SELECT count(*) INTO durable_catalog_count
    FROM logical_workflow_reusable_workflow_catalog
    WHERE run_id = NEW.run_id;

    SELECT count(*) INTO durable_invocation_count
    FROM logical_workflow_reusable_invocation_expansions
    WHERE run_id = NEW.run_id;

    SELECT count(*) INTO durable_job_count
    FROM logical_workflow_reusable_expanded_jobs
    WHERE run_id = NEW.run_id;

    SELECT COALESCE(max(depth), 0) INTO durable_maximum_depth
    FROM logical_workflow_reusable_invocation_expansions
    WHERE run_id = NEW.run_id;

    IF durable_catalog_count <> expected_catalog_count
        OR durable_invocation_count <> expected_invocation_count
        OR durable_job_count <> expected_job_count
        OR durable_maximum_depth <> expected_maximum_depth
    THEN
        RAISE EXCEPTION 'reusable workflow expansion counts disagree with its replay receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_counts_exact';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_runs AS marker
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN workflow_definitions AS workflow ON workflow.id = run.workflow_id
        JOIN workflow_snapshots AS snapshot ON snapshot.id = run.snapshot_id
        JOIN logical_workflow_reusable_invocation_expansions AS root
          ON root.run_id = marker.run_id
         AND root.invocation_id = marker.root_invocation_id
         AND root.depth = 0
        JOIN logical_workflow_reusable_workflow_catalog AS catalog
          ON catalog.run_id = root.run_id
         AND catalog.catalog_entry_id = root.catalog_entry_id
        WHERE marker.run_id = NEW.run_id
          AND marker.root_invocation_id = expected_root_invocation_id
          AND marker.admission_graph_sealed_at_ms IS NOT NULL
          AND catalog.workflow_path = workflow.path
          AND catalog.source_digest = snapshot.source_digest
          AND catalog.source_revision = run.head_sha
          AND catalog.source_object_key = snapshot.source_object_key
          AND catalog.source_size_bytes = snapshot.source_size_bytes
          AND catalog.source_media_type = snapshot.source_media_type
          AND catalog.plan_digest = run.plan_digest
          AND catalog.plan_object_key = run.plan_object_key
          AND catalog.plan_size_bytes = run.plan_size_bytes
          AND catalog.plan_media_type = run.plan_media_type
          AND catalog.plan_schema = run.plan_schema
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion lacks its exact sealed root'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_root_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS child
        LEFT JOIN logical_workflow_reusable_invocation_expansions AS parent
          ON parent.run_id = child.run_id
         AND parent.invocation_id = child.parent_invocation_id
        WHERE child.run_id = NEW.run_id
          AND child.depth > 0
          AND (
              parent.invocation_id IS NULL
              OR child.depth <> parent.depth + 1
              OR child.call_path[1:parent.depth + 1] <> parent.call_path
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion parent lineage is inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_parent_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS invocation
        JOIN logical_workflow_reusable_workflow_catalog AS catalog
          ON catalog.run_id = invocation.run_id
         AND catalog.catalog_entry_id = invocation.catalog_entry_id
        JOIN workflow_runs AS run ON run.id = invocation.run_id
        WHERE invocation.run_id = NEW.run_id
          AND (
              invocation.workflow_path <> catalog.workflow_path
              OR catalog.source_revision <> run.head_sha
              OR (
                  invocation.depth > 0
                  AND catalog.invocation_contract_digest IS NULL
              )
              OR (
                  SELECT count(*)
                  FROM logical_workflow_reusable_expanded_jobs AS job
                  WHERE job.run_id = invocation.run_id
                    AND job.invocation_id = invocation.invocation_id
              ) <> catalog.logical_job_count
              OR (
                  SELECT count(*)
                  FROM logical_workflow_reusable_expanded_jobs AS job
                  WHERE job.run_id = invocation.run_id
                    AND job.invocation_id = invocation.invocation_id
                    AND job.execution_kind = 'reusable_workflow'
              ) <> catalog.reusable_call_count
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow catalog and expanded invocation disagree'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_catalog_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS invocation
        CROSS JOIN LATERAL unnest(invocation.call_path) AS path(value)
        WHERE invocation.run_id = NEW.run_id
        GROUP BY invocation.invocation_id
        HAVING count(*) <> count(DISTINCT path.value)
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion contains a call cycle'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_acyclic';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS child
        JOIN logical_workflow_reusable_expanded_jobs AS caller
          ON caller.run_id = child.run_id
         AND caller.invocation_id = child.parent_invocation_id
         AND caller.logical_job_id = child.caller_logical_job_id
        WHERE child.run_id = NEW.run_id
          AND child.depth > 0
          AND caller.execution_kind <> 'reusable_workflow'
    ) OR EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_expanded_jobs AS caller
        WHERE caller.run_id = NEW.run_id
          AND caller.execution_kind = 'reusable_workflow'
          AND NOT EXISTS (
              SELECT 1
              FROM logical_workflow_reusable_invocation_expansions AS child
              WHERE child.run_id = caller.run_id
                AND child.parent_invocation_id = caller.invocation_id
                AND child.caller_logical_job_id = caller.logical_job_id
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow callsites and child invocations disagree'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_callsites_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS invocation
        LEFT JOIN logical_workflow_reusable_permission_snapshots AS permissions
          ON permissions.run_id = invocation.run_id
         AND permissions.invocation_id = invocation.invocation_id
         AND permissions.permission_digest = invocation.permission_digest
        WHERE invocation.run_id = NEW.run_id
          AND permissions.invocation_id IS NULL
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion lacks an exact permission reduction'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_permissions_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS child
        JOIN logical_workflow_reusable_invocation_expansions AS parent
          ON parent.run_id = child.run_id
         AND parent.invocation_id = child.parent_invocation_id
        JOIN logical_workflow_reusable_permission_snapshots AS child_permissions
          ON child_permissions.run_id = child.run_id
         AND child_permissions.invocation_id = child.invocation_id
        JOIN logical_workflow_reusable_permission_snapshots AS parent_permissions
          ON parent_permissions.run_id = parent.run_id
         AND parent_permissions.invocation_id = parent.invocation_id
        WHERE child.run_id = NEW.run_id
          AND child.depth > 0
          AND (
              CASE child_permissions.default_level
                  WHEN 'none' THEN 0 WHEN 'read' THEN 1 ELSE 2
              END > CASE parent_permissions.default_level
                  WHEN 'none' THEN 0 WHEN 'read' THEN 1 ELSE 2
              END
              OR EXISTS (
                  SELECT 1
                  FROM (
                      SELECT permission_name
                      FROM logical_workflow_reusable_permission_grants
                      WHERE run_id = child.run_id
                        AND invocation_id = child.invocation_id
                      UNION
                      SELECT permission_name
                      FROM logical_workflow_reusable_permission_grants
                      WHERE run_id = parent.run_id
                        AND invocation_id = parent.invocation_id
                  ) AS scope
                  LEFT JOIN logical_workflow_reusable_permission_grants AS child_grant
                    ON child_grant.run_id = child.run_id
                   AND child_grant.invocation_id = child.invocation_id
                   AND child_grant.permission_name = scope.permission_name
                  LEFT JOIN logical_workflow_reusable_permission_grants AS parent_grant
                    ON parent_grant.run_id = parent.run_id
                   AND parent_grant.invocation_id = parent.invocation_id
                   AND parent_grant.permission_name = scope.permission_name
                  WHERE CASE COALESCE(
                      child_grant.permission_level,
                      child_permissions.default_level
                  ) WHEN 'none' THEN 0 WHEN 'read' THEN 1 ELSE 2 END
                  > CASE COALESCE(
                      parent_grant.permission_level,
                      parent_permissions.default_level
                  ) WHEN 'none' THEN 0 WHEN 'read' THEN 1 ELSE 2 END
              )
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow permissions exceed their caller ceiling'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_permission_reduction';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS invocation
        WHERE invocation.run_id = NEW.run_id
          AND (
              invocation.input_binding_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_input_bindings AS input
                  WHERE input.run_id = invocation.run_id
                    AND input.invocation_id = invocation.invocation_id
              )
              OR invocation.secret_binding_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_secret_bindings AS secret
                  WHERE secret.run_id = invocation.run_id
                    AND secret.invocation_id = invocation.invocation_id
              )
              OR invocation.output_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_outputs AS output
                  WHERE output.run_id = invocation.run_id
                    AND output.invocation_id = invocation.invocation_id
              )
              OR invocation.permission_grant_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_permission_grants AS permission_grant
                  WHERE permission_grant.run_id = invocation.run_id
                    AND permission_grant.invocation_id = invocation.invocation_id
              )
              OR invocation.dependency_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_expanded_dependencies AS dependency
                  WHERE dependency.run_id = invocation.run_id
                    AND dependency.invocation_id = invocation.invocation_id
              )
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow typed boundary counts are inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_contract_counts_exact';
    END IF;
    RETURN NULL;
END;
$function$;

CREATE OR REPLACE FUNCTION automata_guard_provider_delivery_workflow_inventory()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
    inbox provider_delivery_inbox%ROWTYPE;
    manifest_digest BYTEA;
    authenticated_source_revision BYTEA;
BEGIN
    SELECT * INTO inbox
    FROM provider_delivery_inbox
    WHERE id = NEW.inbox_id AND tenant_id = NEW.tenant_id
    FOR SHARE;
    SELECT evidence.provider_manifest_digest,
           evidence.github_check_head_sha
      INTO manifest_digest, authenticated_source_revision
    FROM github_provider_delivery_evidence AS evidence
    WHERE evidence.provider_delivery_id = NEW.inbox_id
      AND evidence.tenant_id = NEW.tenant_id
    FOR SHARE;
    IF inbox.id IS NULL
        OR manifest_digest IS NULL
        OR inbox.state <> 'claimed'
        OR NEW.registered_at_ms < inbox.claimed_at_ms
        OR NEW.registered_at_ms >= inbox.claim_expires_at_ms
        OR NEW.manifest_digest <> manifest_digest
        OR NEW.source_revision <> authenticated_source_revision
    THEN
        RAISE EXCEPTION 'provider delivery workflow inventory lacks live authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_inventory_live_authority';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION automata_event_subject_selection_digest(smallint, smallint, bytea, uuid, text, uuid, smallint, uuid, text, text, bytea, bytea, bytea, bigint)
 RETURNS bytea
 LANGUAGE sql
 IMMUTABLE PARALLEL SAFE STRICT
AS $function$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.event-subject-selection.v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || pg_catalog.int2send($1)
    || pg_catalog.int2send($2)
    || $3
    || pg_catalog.uuid_send($4)
    || automata_event_subject_digest_part(pg_catalog.convert_to($5, 'UTF8'))
    || pg_catalog.uuid_send($6)
    || pg_catalog.int2send($7)
    || pg_catalog.uuid_send($8)
    || automata_event_subject_digest_part(pg_catalog.convert_to($9, 'UTF8'))
    || automata_event_subject_digest_part(pg_catalog.convert_to($10, 'UTF8'))
    || automata_event_subject_digest_part($11)
    || $12
    || $13
    || pg_catalog.int8send($14)
)
$function$;

CREATE OR REPLACE FUNCTION automata_event_subject_progress_insert_exact()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM 1
    FROM event_subject_selections AS selection
    JOIN event_control_subjects AS control
      ON control.tenant_id = selection.tenant_id
     AND control.subject_id = selection.subject_id
     AND control.selection_digest = selection.selection_digest
    WHERE selection.tenant_id = NEW.tenant_id
      AND selection.subject_id = NEW.subject_id
      AND selection.selection_digest = NEW.selection_digest
      AND control.registered_at_ms >= selection.selected_at_ms
      AND NEW.recorded_at_ms >= control.registered_at_ms;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'event progress precedes selection or control registration'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'event_subject_progress_timeline_exact';
    END IF;

    IF NEW.outcome_kind <> 'admitted' THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM event_subject_selections AS selection
    JOIN workflow_runs AS run
      ON run.id = NEW.run_id
     AND run.repository_id = selection.repository_id
    JOIN workflow_definitions AS workflow
      ON workflow.repository_id = run.repository_id
     AND workflow.id = run.workflow_id
     AND workflow.path = selection.workflow_path
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
     AND snapshot.source_digest = selection.source_digest
    WHERE selection.tenant_id = NEW.tenant_id
      AND selection.subject_id = NEW.subject_id
      AND selection.selection_digest = NEW.selection_digest
      AND run.event_name = selection.event_name
      AND run.head_sha = selection.source_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'admitted event-subject progress does not match its selected workflow run'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'event_subject_progress_admitted_run_exact';
    END IF;
    RETURN NEW;
END;
$function$;

ALTER TABLE event_subject_selections ADD CONSTRAINT event_subject_selections_shape CHECK (((subject_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (origin_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (selection_schema = 1) AND (octet_length(origin_registry_digest) = 32) AND (octet_length(source_digest) = 32) AND (octet_length(authority_digest) = 32) AND (octet_length(selection_digest) = 32) AND (selected_at_ms >= 0) AND ((octet_length(event_name) >= 1) AND (octet_length(event_name) <= 128)) AND (event_name ~ '^[a-z][a-z0-9._-]*$'::text) AND ((octet_length(workflow_path) >= 1) AND (octet_length(workflow_path) <= 1024)) AND (btrim(workflow_path) = workflow_path) AND (workflow_path !~ '[[:cntrl:]\\]'::text) AND ("left"(workflow_path, 1) <> '/'::text) AND (workflow_path !~ '(^|/)(\.|\.\.)(/|$)'::text) AND (workflow_path !~ '//'::text) AND (octet_length(source_revision) = ANY (ARRAY[20, 32])) AND (source_revision <> decode(repeat('00'::text, octet_length(source_revision)), 'hex'::text))));
ALTER TABLE github_check_subjects ADD CONSTRAINT github_check_subjects_sha CHECK (((octet_length(head_sha) = ANY (ARRAY[20, 32])) AND (head_sha <> decode(repeat('00'::text, octet_length(head_sha)), 'hex'::text))));
ALTER TABLE github_provider_delivery_evidence ADD CONSTRAINT github_provider_delivery_evidence_authenticated_event CHECK ((((authenticated_event_envelope_version = 1) AND (authenticated_event_name = ANY (ARRAY['push'::text, 'pull_request'::text, 'merge_group'::text])) AND ((octet_length(authenticated_event_git_ref) >= 6) AND (octet_length(authenticated_event_git_ref) <= 1024)) AND (authenticated_event_git_ref ~~ 'refs/%'::text) AND (authenticated_event_git_ref !~ '[[:cntrl:]]'::text) AND (authenticated_event_source_revision IS NULL) AND (authenticated_event_source_authority IS NULL)) OR ((authenticated_event_envelope_version = 1) AND (authenticated_event_name = 'repository_dispatch'::text) AND ((octet_length(authenticated_event_git_ref) >= 12) AND (octet_length(authenticated_event_git_ref) <= 1024)) AND (authenticated_event_git_ref ~~ 'refs/heads/%'::text) AND (authenticated_event_git_ref !~ '[[:cntrl:]]'::text) AND (octet_length(authenticated_event_source_revision) = ANY (ARRAY[20, 32])) AND (authenticated_event_source_revision <> decode(repeat('00'::text, octet_length(authenticated_event_source_revision)), 'hex'::text)) AND (((repository_visibility = 'public'::text) AND (authenticated_event_source_authority = 'public_anonymous'::text)) OR ((repository_visibility = 'private'::text) AND (authenticated_event_source_authority = 'private_source_authority'::text))))));
ALTER TABLE github_provider_delivery_evidence ADD CONSTRAINT github_provider_delivery_evidence_digest_shape CHECK (((octet_length(provider_manifest_digest) = 32) AND (octet_length(authenticated_webhook_verifier_fingerprint_sha256) = 32) AND (authenticated_webhook_verifier_fingerprint_sha256 <> decode(repeat('00'::text, 32), 'hex'::text)) AND (octet_length(checks_authority_identity_digest) = 32) AND ((private_source_authority_identity_digest IS NULL) OR (octet_length(private_source_authority_identity_digest) = 32)) AND (octet_length(github_check_head_sha) = ANY (ARRAY[20, 32])) AND (github_check_head_sha <> decode(repeat('00'::text, octet_length(github_check_head_sha)), 'hex'::text))));
ALTER TABLE github_schedule_check_evidence ADD CONSTRAINT github_schedule_check_evidence_shape CHECK (((entry_ordinal >= 0) AND (entry_ordinal <= 255) AND (scheduled_at_ms >= 0) AND (provider_manifest_revision > 0) AND (github_repository_owner_id > 0) AND (octet_length(provider_manifest_digest) = 32) AND (octet_length(checks_authority_identity_digest) = 32) AND (checks_authority_app_configuration_revision > 0) AND (checks_authority_policy_revision > 0) AND (octet_length(source_revision) = ANY (ARRAY[20, 32])) AND automata_github_provider_git_ref_canonical(default_branch_ref) AND (github_check_head_sha = source_revision) AND (recorded_at_ms >= 0)));
ALTER TABLE github_schedule_registry_revisions ADD CONSTRAINT github_schedule_registry_revisions_source_shape CHECK (((default_branch_ref ~ '^refs/heads/[^[:cntrl:][:space:]]+$'::text) AND ((octet_length(default_branch_ref) >= 12) AND (octet_length(default_branch_ref) <= 1024)) AND (octet_length(source_revision) = ANY (ARRAY[20, 32])) AND (source_revision <> decode(repeat('00'::text, octet_length(source_revision)), 'hex'::text))));
ALTER TABLE github_schedule_workflow_run_subject_evidence ADD CONSTRAINT github_schedule_workflow_run_subject_evidence_shape CHECK (((admission_claim_attempt >= 1) AND (admission_claim_attempt <= 20) AND (github_repository_owner_id > 0) AND (admission_claim_fence > 0) AND (admission_claimed_at_ms >= 0) AND (admission_claim_expires_at_ms > admission_claimed_at_ms) AND (admitted_at_ms >= admission_claimed_at_ms) AND (admitted_at_ms < admission_claim_expires_at_ms) AND (octet_length(github_check_head_sha) = ANY (ARRAY[20, 32])) AND (octet_length(source_digest) = 32) AND (event_name = 'schedule'::text) AND (octet_length(event_digest) = 32) AND automata_github_provider_git_ref_canonical(git_ref) AND (workflow_plan_schema = 1) AND (octet_length(plan_digest) = 32) AND (octet_length(logical_admission_digest) = 32) AND (octet_length(subject_evidence_sha256) = 32) AND (workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'::text) AND (workflow_path !~ '[[:cntrl:]\\]'::text)));
ALTER TABLE github_workflow_rerun_subject_evidence ADD CONSTRAINT github_workflow_rerun_subject_evidence_shape CHECK (((github_repository_owner_id > 0) AND (octet_length(github_check_head_sha) = ANY (ARRAY[20, 32])) AND (github_check_head_sha <> decode(repeat('00'::text, octet_length(github_check_head_sha)), 'hex'::text)) AND (octet_length(source_digest) = 32) AND ((octet_length(event_name) >= 1) AND (octet_length(event_name) <= 1024)) AND (event_name !~ '[[:cntrl:]]'::text) AND (octet_length(event_digest) = 32) AND automata_github_provider_git_ref_canonical(git_ref) AND (workflow_plan_schema = 1) AND (octet_length(plan_digest) = 32) AND (octet_length(logical_admission_digest) = 32) AND (admitted_at_ms >= 0) AND (octet_length(subject_evidence_sha256) = 32) AND (workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'::text) AND (workflow_path !~ '[[:cntrl:]\\]'::text)));
ALTER TABLE github_workflow_run_subject_evidence ADD CONSTRAINT github_workflow_run_subject_evidence_digest_shape CHECK (((octet_length(github_check_head_sha) = ANY (ARRAY[20, 32])) AND (github_check_head_sha <> decode(repeat('00'::text, octet_length(github_check_head_sha)), 'hex'::text)) AND (octet_length(source_digest) = 32) AND (octet_length(event_digest) = 32) AND (octet_length(plan_digest) = 32) AND (octet_length(logical_admission_digest) = 32) AND (octet_length(subject_evidence_sha256) = 32)));
ALTER TABLE logical_workflow_reusable_workflow_catalog ADD CONSTRAINT logical_workflow_reusable_catalog_revision_shape CHECK (((octet_length(source_revision) = ANY (ARRAY[20, 32])) AND (source_revision <> decode(repeat('00'::text, octet_length(source_revision)), 'hex'::text))));
ALTER TABLE provider_delivery_workflow_inventories ADD CONSTRAINT provider_delivery_workflow_inventories_shape CHECK (((octet_length(manifest_digest) = 32) AND (octet_length(repository_source_digest) = 32) AND (octet_length(inventory_digest) = 32) AND (octet_length(source_revision) = ANY (ARRAY[20, 32])) AND (source_revision <> decode(repeat('00'::text, octet_length(source_revision)), 'hex'::text)) AND ((workflow_count >= 0) AND (workflow_count <= 256)) AND (registered_at_ms >= 0)));
ALTER TABLE workflow_rerun_check_evidence ADD CONSTRAINT workflow_rerun_check_evidence_shape CHECK (((provider_manifest_revision > 0) AND (octet_length(provider_manifest_digest) = 32) AND (octet_length(github_check_head_sha) = ANY (ARRAY[20, 32])) AND (github_check_head_sha <> decode(repeat('00'::text, octet_length(github_check_head_sha)), 'hex'::text)) AND (octet_length(checks_authority_identity_digest) = 32) AND (checks_authority_app_configuration_revision > 0) AND (checks_authority_policy_revision > 0) AND (num_nonnulls(private_source_authority_id, private_source_authority_identity_digest, private_source_authority_app_configuration_revision, private_source_authority_policy_revision) = ANY (ARRAY[0, 4])) AND ((private_source_authority_identity_digest IS NULL) OR ((octet_length(private_source_authority_identity_digest) = 32) AND (private_source_authority_app_configuration_revision > 0) AND (private_source_authority_policy_revision > 0))) AND (recorded_at_ms >= 0)));
ALTER TABLE event_subject_selections ADD CONSTRAINT event_subject_selections_digest_canonical CHECK ((selection_digest = automata_event_subject_selection_digest(selection_schema, origin_registry_version, origin_registry_digest, subject_id, tenant_id, repository_id, origin_kind_code, origin_id, event_name, workflow_path, source_revision, source_digest, authority_digest, selected_at_ms)));
ALTER TABLE github_schedule_check_evidence ADD CONSTRAINT github_schedule_check_evidence_registry FOREIGN KEY (tenant_id, repository_id, provider_connection_id, registry_id, provider_manifest_revision, provider_manifest_digest, default_branch_ref, source_revision, github_repository_owner_id) REFERENCES github_schedule_registry_revisions(tenant_id, repository_id, provider_connection_id, registry_id, manifest_revision, manifest_digest, default_branch_ref, source_revision, github_repository_owner_id) ON DELETE RESTRICT;
CREATE VIEW github_workflow_run_base_manifest_origins AS
 SELECT delivery_run.tenant_id,
    delivery_run.repository_id,
    delivery_run.workflow_id,
    delivery_run.snapshot_id,
    delivery_run.run_id,
    delivery_run.root_invocation_id,
    'provider_delivery'::text AS origin_kind,
    delivery_run.provider_delivery_id AS origin_id,
    'provider_delivery'::text AS admission_idempotency_kind,
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
   FROM github_workflow_run_subject_evidence delivery_run
     JOIN github_provider_delivery_evidence delivery ON delivery.tenant_id = delivery_run.tenant_id AND delivery.repository_id = delivery_run.repository_id AND delivery.provider_delivery_id = delivery_run.provider_delivery_id
UNION ALL
 SELECT schedule_run.tenant_id,
    schedule_run.repository_id,
    schedule_run.workflow_id,
    schedule_run.snapshot_id,
    schedule_run.run_id,
    schedule_run.root_invocation_id,
    'scheduled_fire'::text AS origin_kind,
    schedule_run.schedule_fire_id AS origin_id,
    'operation'::text AS admission_idempotency_kind,
    schedule_run.schedule_fire_id::text AS admission_idempotency_key,
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
    manifest.webhook_verifier_fingerprint_sha256 AS authenticated_webhook_verifier_fingerprint_sha256,
    manifest.webhook_verifier_revision AS authenticated_webhook_verifier_revision,
    schedule_check.checks_authority_id,
    schedule_check.checks_authority_identity_digest,
    schedule_check.checks_authority_app_configuration_revision,
    schedule_check.checks_authority_policy_revision,
    registry.private_source_authority_id,
    registry.private_source_authority_identity_digest,
    registry.private_source_authority_app_configuration_revision,
    registry.private_source_authority_policy_revision
   FROM github_schedule_workflow_run_subject_evidence schedule_run
     JOIN github_schedule_check_evidence schedule_check ON schedule_check.schedule_fire_id = schedule_run.schedule_fire_id AND schedule_check.tenant_id = schedule_run.tenant_id AND schedule_check.repository_id = schedule_run.repository_id AND schedule_check.github_check_subject_id = schedule_run.github_check_subject_id
     JOIN github_schedule_registry_revisions registry ON registry.tenant_id = schedule_check.tenant_id AND registry.repository_id = schedule_check.repository_id AND registry.provider_connection_id = schedule_check.provider_connection_id AND registry.registry_id = schedule_check.registry_id AND registry.manifest_revision = schedule_check.provider_manifest_revision AND registry.manifest_digest = schedule_check.provider_manifest_digest AND registry.default_branch_ref = schedule_check.default_branch_ref AND registry.source_revision = schedule_check.source_revision
     JOIN github_provider_manifest_revisions manifest ON manifest.tenant_id = schedule_check.tenant_id AND manifest.repository_id = schedule_check.repository_id AND manifest.provider_connection_id = schedule_check.provider_connection_id AND manifest.manifest_revision = schedule_check.provider_manifest_revision AND manifest.manifest_digest = schedule_check.provider_manifest_digest;;
CREATE VIEW github_workflow_run_manifest_origins AS
 SELECT github_workflow_run_base_manifest_origins.tenant_id,
    github_workflow_run_base_manifest_origins.repository_id,
    github_workflow_run_base_manifest_origins.workflow_id,
    github_workflow_run_base_manifest_origins.snapshot_id,
    github_workflow_run_base_manifest_origins.run_id,
    github_workflow_run_base_manifest_origins.root_invocation_id,
    github_workflow_run_base_manifest_origins.origin_kind,
    github_workflow_run_base_manifest_origins.origin_id,
    github_workflow_run_base_manifest_origins.admission_idempotency_kind,
    github_workflow_run_base_manifest_origins.admission_idempotency_key,
    github_workflow_run_base_manifest_origins.github_check_subject_id,
    github_workflow_run_base_manifest_origins.github_check_head_sha,
    github_workflow_run_base_manifest_origins.workflow_path,
    github_workflow_run_base_manifest_origins.source_digest,
    github_workflow_run_base_manifest_origins.event_name,
    github_workflow_run_base_manifest_origins.event_digest,
    github_workflow_run_base_manifest_origins.git_ref,
    github_workflow_run_base_manifest_origins.workflow_plan_schema,
    github_workflow_run_base_manifest_origins.plan_digest,
    github_workflow_run_base_manifest_origins.logical_admission_digest,
    github_workflow_run_base_manifest_origins.admitted_at_ms,
    github_workflow_run_base_manifest_origins.subject_evidence_sha256,
    github_workflow_run_base_manifest_origins.provider_connection_id,
    github_workflow_run_base_manifest_origins.provider_installation_id,
    github_workflow_run_base_manifest_origins.github_repository_id,
    github_workflow_run_base_manifest_origins.github_repository_owner_id,
    github_workflow_run_base_manifest_origins.github_repository_name,
    github_workflow_run_base_manifest_origins.repository_visibility,
    github_workflow_run_base_manifest_origins.provider_manifest_revision,
    github_workflow_run_base_manifest_origins.provider_manifest_digest,
    github_workflow_run_base_manifest_origins.authenticated_webhook_verifier_fingerprint_sha256,
    github_workflow_run_base_manifest_origins.authenticated_webhook_verifier_revision,
    github_workflow_run_base_manifest_origins.checks_authority_id,
    github_workflow_run_base_manifest_origins.checks_authority_identity_digest,
    github_workflow_run_base_manifest_origins.checks_authority_app_configuration_revision,
    github_workflow_run_base_manifest_origins.checks_authority_policy_revision,
    github_workflow_run_base_manifest_origins.private_source_authority_id,
    github_workflow_run_base_manifest_origins.private_source_authority_identity_digest,
    github_workflow_run_base_manifest_origins.private_source_authority_app_configuration_revision,
    github_workflow_run_base_manifest_origins.private_source_authority_policy_revision
   FROM github_workflow_run_base_manifest_origins
UNION ALL
 SELECT origin.tenant_id,
    origin.repository_id,
    rerun.workflow_id,
    rerun.snapshot_id,
    attempt.run_id,
    marker.root_invocation_id,
    'workflow_rerun'::text AS origin_kind,
    request.operation_id AS origin_id,
    'operation'::text AS admission_idempotency_kind,
    'workflow-rerun:'::text || request.operation_id::text AS admission_idempotency_key,
    run_evidence.github_check_subject_id,
    run_evidence.github_check_head_sha,
    run_evidence.workflow_path,
    run_evidence.source_digest,
    run_evidence.event_name,
    run_evidence.event_digest,
    run_evidence.git_ref,
    run_evidence.workflow_plan_schema,
    run_evidence.plan_digest,
    run_evidence.logical_admission_digest,
    run_evidence.admitted_at_ms,
    run_evidence.subject_evidence_sha256,
    check_evidence.provider_connection_id,
    origin.provider_installation_id,
    origin.github_repository_id,
    origin.github_repository_owner_id,
    origin.github_repository_name,
    origin.repository_visibility,
    check_evidence.provider_manifest_revision,
    check_evidence.provider_manifest_digest,
    origin.authenticated_webhook_verifier_fingerprint_sha256,
    origin.authenticated_webhook_verifier_revision,
    check_evidence.checks_authority_id,
    check_evidence.checks_authority_identity_digest,
    check_evidence.checks_authority_app_configuration_revision,
    check_evidence.checks_authority_policy_revision,
    check_evidence.private_source_authority_id,
    check_evidence.private_source_authority_identity_digest,
    check_evidence.private_source_authority_app_configuration_revision,
    check_evidence.private_source_authority_policy_revision
   FROM workflow_rerun_attempts attempt
     JOIN workflow_rerun_check_evidence check_evidence ON check_evidence.run_id = attempt.run_id AND check_evidence.source_run_id = attempt.source_run_id
     JOIN workflow_rerun_requests request ON request.tenant_id = check_evidence.tenant_id AND request.operation_id = check_evidence.operation_id AND request.rerun_run_id = attempt.run_id AND request.committed_at_ms = attempt.created_at_ms
     JOIN workflow_runs rerun ON rerun.id = attempt.run_id
     JOIN logical_workflow_runs marker ON marker.run_id = attempt.run_id
     JOIN github_workflow_rerun_subject_evidence run_evidence ON run_evidence.tenant_id = check_evidence.tenant_id AND run_evidence.operation_id = check_evidence.operation_id AND run_evidence.run_id = check_evidence.run_id AND run_evidence.source_run_id = check_evidence.source_run_id AND run_evidence.github_check_subject_id = check_evidence.github_check_subject_id AND run_evidence.github_check_head_sha = check_evidence.github_check_head_sha AND run_evidence.admitted_at_ms = check_evidence.recorded_at_ms
     JOIN github_workflow_run_base_manifest_origins origin ON origin.run_id = attempt.root_run_id AND origin.tenant_id = check_evidence.tenant_id AND origin.repository_id = check_evidence.repository_id AND origin.provider_connection_id = check_evidence.provider_connection_id AND origin.provider_manifest_revision = check_evidence.provider_manifest_revision AND origin.provider_manifest_digest = check_evidence.provider_manifest_digest
  WHERE attempt.source_run_id IS NOT NULL;;
