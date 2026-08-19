-- Publish one revision gate plus concrete jobs, never workflow bookkeeping.

ALTER TABLE github_provider_delivery_evidence
    DROP CONSTRAINT github_provider_delivery_evidence_aggregate_check_kind;
UPDATE github_provider_delivery_evidence
SET aggregate_check_kind = 'jobs_only'
WHERE aggregate_check_kind = 'auxiliary';
ALTER TABLE github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_aggregate_check_kind
    CHECK (aggregate_check_kind IN ('required', 'jobs_only'));

CREATE OR REPLACE FUNCTION automata_create_github_check_projection_outbox()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.subject_kind = 'job'
       OR EXISTS (
           SELECT 1
           FROM github_provider_delivery_evidence AS evidence
           WHERE evidence.github_check_subject_id = NEW.id
             AND evidence.provider_delivery_id = NEW.provider_delivery_id
             AND evidence.tenant_id = NEW.tenant_id
             AND evidence.aggregate_check_kind = 'required'
       )
    THEN
        INSERT INTO github_check_projection_outbox (subject_id, state_updated_at_ms)
        VALUES (NEW.id, NEW.created_at_ms);
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION automata_github_check_subject_delivery_evidence_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    authority RECORD;
    aggregate_check_name TEXT;
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
        SELECT manifest.check_name
          INTO aggregate_check_name
        FROM github_workflow_run_manifest_origins AS origin
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        WHERE origin.run_id = NEW.workflow_run_id
        FOR SHARE OF manifest;
        IF aggregate_check_name IS NULL
           OR NEW.check_name = aggregate_check_name
        THEN
            RAISE EXCEPTION 'GitHub job Check collides with its aggregate name authority'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_job_name_reserved';
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
           inbox_source.accepted_at_ms,
           manifest_source.check_subject_key,
           manifest_source.github_app_id,
           manifest_source.check_name
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

    IF authority.repository_id IS NULL
        OR NEW.origin_kind <> 'provider_delivery'
        OR NEW.repository_id <> authority.repository_id
        OR NEW.provider_connection_id <> authority.provider_connection_id
        OR NEW.provider_installation_id <> authority.provider_installation_id
        OR NEW.github_repository_id <> authority.github_repository_id
        OR NEW.github_repository_name <> authority.github_repository_name
        OR NEW.github_app_id <> authority.github_app_id
        OR NEW.head_sha <> authority.github_check_head_sha
        OR NEW.check_name IS DISTINCT FROM authority.check_name
        OR NEW.created_at_ms <> authority.accepted_at_ms
        OR NEW.id <> authority.github_check_subject_id
        OR NEW.subject_key <> authority.check_subject_key
    THEN
        RAISE EXCEPTION 'GitHub Check subject does not match its signed delivery evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_delivery_evidence_exact';
    END IF;
    RETURN NEW;
END;
$$;

DROP FUNCTION automata_github_auxiliary_check_name(TEXT);
DROP FUNCTION automata_github_required_check_name(TEXT);
DROP FUNCTION automata_github_workflow_check_name(TEXT, TEXT);
