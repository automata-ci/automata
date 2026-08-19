-- Isolate a fresh required Check name for revision-testing events.

ALTER TABLE github_provider_delivery_evidence
    ADD COLUMN aggregate_check_kind text NOT NULL DEFAULT 'required';
ALTER TABLE github_provider_delivery_evidence
    ALTER COLUMN aggregate_check_kind DROP DEFAULT;
ALTER TABLE github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_aggregate_check_kind
    CHECK (aggregate_check_kind IN ('required', 'auxiliary'));

CREATE FUNCTION automata_github_auxiliary_check_name(TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE PARALLEL SAFE STRICT
AS $$
SELECT left($1, 237) || ' / auxiliary event'
$$;

CREATE FUNCTION automata_github_required_check_name(TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE PARALLEL SAFE STRICT
AS $$
SELECT left($1, 244) || ' / required'
$$;

CREATE FUNCTION automata_github_required_check_not_skipped()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.desired_conclusion = 'skipped'
       AND EXISTS (
           SELECT 1
           FROM github_provider_delivery_evidence AS evidence
           WHERE evidence.github_check_subject_id = NEW.id
             AND evidence.provider_delivery_id = NEW.provider_delivery_id
             AND evidence.tenant_id = NEW.tenant_id
             AND evidence.aggregate_check_kind = 'required'
       )
    THEN
        RAISE EXCEPTION 'required GitHub Check aggregate cannot be skipped'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_required_not_skipped';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER github_check_subjects_required_not_skipped
BEFORE UPDATE OF desired_conclusion ON github_check_subjects
FOR EACH ROW
EXECUTE FUNCTION automata_github_required_check_not_skipped();

CREATE OR REPLACE FUNCTION automata_github_check_subject_delivery_evidence_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    authority RECORD;
    workflow_authorized BOOLEAN := FALSE;
    expected_check_name TEXT;
BEGIN
    IF NEW.subject_kind = 'job' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM github_check_subjects AS parent
            WHERE parent.id = NEW.parent_subject_id
              AND parent.tenant_id = NEW.tenant_id
              AND parent.repository_id = NEW.repository_id
              AND parent.subject_kind = 'workflow'
              AND parent.origin_kind = NEW.origin_kind
              AND parent.provider_delivery_id IS NOT DISTINCT FROM
                  NEW.provider_delivery_id
              AND parent.workflow_rerun_run_id IS NOT DISTINCT FROM
                  NEW.workflow_rerun_run_id
              AND parent.provider_connection_id = NEW.provider_connection_id
              AND parent.provider_installation_id = NEW.provider_installation_id
              AND parent.github_repository_id = NEW.github_repository_id
              AND parent.github_repository_name = NEW.github_repository_name
              AND parent.github_app_id = NEW.github_app_id
              AND parent.head_sha = NEW.head_sha
            FOR SHARE OF parent
        ) THEN
            RAISE EXCEPTION 'GitHub job Check does not match its workflow authority'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_parent_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.origin_kind = 'workflow_rerun' THEN
        RETURN NEW;
    END IF;
    SELECT evidence_source.repository_id,
           evidence_source.provider_connection_id,
           evidence_source.provider_installation_id,
           evidence_source.github_repository_id,
           evidence_source.github_repository_name,
           evidence_source.github_check_subject_id,
           evidence_source.github_check_head_sha,
           evidence_source.aggregate_check_kind,
           inbox_source.accepted_at_ms,
           inbox_source.state AS inbox_state,
           manifest_source.workflow_selection_kind,
           manifest_source.check_subject_key,
           manifest_source.github_app_id,
           manifest_source.check_name,
           manifest_source.manifest_digest
      INTO authority
    FROM github_provider_delivery_evidence AS evidence_source
    JOIN provider_delivery_inbox AS inbox_source
      ON inbox_source.id = evidence_source.provider_delivery_id
     AND inbox_source.tenant_id = evidence_source.tenant_id
    JOIN github_provider_manifest_revisions AS manifest_source
      ON manifest_source.tenant_id = evidence_source.tenant_id
     AND manifest_source.repository_id = evidence_source.repository_id
     AND manifest_source.provider_connection_id =
         evidence_source.provider_connection_id
     AND manifest_source.manifest_revision =
         evidence_source.provider_manifest_revision
     AND manifest_source.manifest_digest =
         evidence_source.provider_manifest_digest
    WHERE evidence_source.provider_delivery_id = NEW.provider_delivery_id
      AND evidence_source.tenant_id = NEW.tenant_id
    FOR SHARE OF evidence_source, inbox_source, manifest_source;

    IF FOUND
       AND authority.workflow_selection_kind = 'all_direct'
       AND NEW.id <> authority.github_check_subject_id
    THEN
        SELECT TRUE INTO workflow_authorized
        FROM provider_delivery_workflow_inventories AS inventory
        JOIN provider_delivery_workflow_inventory_entries AS entry
          ON entry.inbox_id = inventory.inbox_id
         AND entry.tenant_id = inventory.tenant_id
        WHERE inventory.inbox_id = NEW.provider_delivery_id
          AND inventory.tenant_id = NEW.tenant_id
          AND inventory.manifest_digest = authority.manifest_digest
          AND entry.workflow_path = NEW.subject_key
          AND (
              entry.source_state = 'ready'
              OR EXISTS (
                  SELECT 1
                  FROM provider_delivery_workflow_progress AS progress
                  WHERE progress.inbox_id = inventory.inbox_id
                    AND progress.tenant_id = inventory.tenant_id
                    AND progress.inventory_digest = inventory.inventory_digest
                    AND progress.workflow_path = entry.workflow_path
                    AND progress.outcome_kind = 'failed'
              )
          )
        FOR SHARE OF inventory, entry;
    END IF;

    expected_check_name := CASE
        WHEN NEW.id <> authority.github_check_subject_id THEN
            automata_github_workflow_check_name(
                authority.check_name,
                NEW.subject_key
            )
        WHEN authority.aggregate_check_kind = 'required' THEN
            automata_github_required_check_name(authority.check_name)
        WHEN authority.aggregate_check_kind = 'auxiliary' THEN
            automata_github_auxiliary_check_name(authority.check_name)
        ELSE NULL
    END;

    IF authority.repository_id IS NULL
        OR NEW.origin_kind <> 'provider_delivery'
        OR NEW.repository_id <> authority.repository_id
        OR NEW.provider_connection_id <> authority.provider_connection_id
        OR NEW.provider_installation_id <> authority.provider_installation_id
        OR NEW.github_repository_id <> authority.github_repository_id
        OR NEW.github_repository_name <> authority.github_repository_name
        OR NEW.github_app_id <> authority.github_app_id
        OR NEW.head_sha <> authority.github_check_head_sha
        OR NEW.check_name IS DISTINCT FROM expected_check_name
        OR NEW.created_at_ms <> authority.accepted_at_ms
        OR NOT (
            NEW.id = authority.github_check_subject_id
            AND NEW.subject_key = authority.check_subject_key
            OR authority.workflow_selection_kind = 'all_direct'
            AND authority.inbox_state = 'claimed'
            AND NEW.id <> authority.github_check_subject_id
            AND workflow_authorized
        )
    THEN
        RAISE EXCEPTION 'GitHub Check subject does not match its signed delivery evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_delivery_evidence_exact';
    END IF;
    RETURN NEW;
END;
$$;
