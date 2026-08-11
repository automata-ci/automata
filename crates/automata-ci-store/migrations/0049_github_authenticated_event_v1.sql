BEGIN;

ALTER TABLE github_provider_delivery_evidence
    ADD COLUMN authenticated_event_envelope_version SMALLINT,
    ADD COLUMN authenticated_event_name TEXT COLLATE "C",
    ADD COLUMN authenticated_event_git_ref TEXT COLLATE "C",
    ADD CONSTRAINT github_provider_delivery_evidence_authenticated_event_v1 CHECK (
        (
            authenticated_event_envelope_version IS NULL
            AND authenticated_event_name IS NULL
            AND authenticated_event_git_ref IS NULL
        ) OR (
            authenticated_event_envelope_version = 1
            AND authenticated_event_name IN ('push', 'pull_request', 'merge_group')
            AND octet_length(authenticated_event_git_ref) BETWEEN 6 AND 1024
            AND authenticated_event_git_ref LIKE 'refs/%'
            AND authenticated_event_git_ref !~ '[[:cntrl:]]'
        )
    );

CREATE FUNCTION automata_github_authenticated_event_v1_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    inbox_media_type TEXT;
BEGIN
    IF NEW.authenticated_event_envelope_version IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT raw_event_media_type
      INTO inbox_media_type
    FROM provider_delivery_inbox
    WHERE id = NEW.provider_delivery_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;

    IF inbox_media_type IS DISTINCT FROM
        'application/vnd.automata.github-authenticated-event.v1+json'
    THEN
        RAISE EXCEPTION 'GitHub authenticated-event envelope does not match its raw object'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_authenticated_event_v1_exact';
    END IF;

    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_provider_delivery_evidence_00_authenticated_event_v1
BEFORE INSERT ON github_provider_delivery_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_github_authenticated_event_v1_exact();

DO $automata_upgrade$
DECLARE
    current_definition TEXT;
    upgraded_definition TEXT;
BEGIN
    SELECT pg_get_functiondef(
        'automata_github_workflow_run_subject_evidence_insert_guard()'::REGPROCEDURE
    )
      INTO current_definition;

    IF strpos(
        current_definition,
        'NEW.event_name <> source_evidence.manifest_event_name'
    ) = 0 OR strpos(
        current_definition,
        'NEW.git_ref <> source_evidence.manifest_git_ref'
    ) = 0
    THEN
        RAISE EXCEPTION 'GitHub authenticated-event guard does not match the expected prior contract'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    upgraded_definition := replace(
        current_definition,
        'NEW.event_name <> source_evidence.manifest_event_name',
        'NEW.event_name <> COALESCE(source_evidence.authenticated_event_name, source_evidence.manifest_event_name)'
    );
    upgraded_definition := replace(
        upgraded_definition,
        'NEW.git_ref <> source_evidence.manifest_git_ref',
        'NEW.git_ref <> COALESCE(source_evidence.authenticated_event_git_ref, source_evidence.manifest_git_ref)'
    );

    IF upgraded_definition = current_definition
        OR strpos(
            upgraded_definition,
            'NEW.event_name <> source_evidence.manifest_event_name'
        ) > 0
        OR strpos(
            upgraded_definition,
            'NEW.git_ref <> source_evidence.manifest_git_ref'
        ) > 0
    THEN
        RAISE EXCEPTION 'GitHub authenticated-event guard upgrade did not match the expected prior contract'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    EXECUTE upgraded_definition;
END;
$automata_upgrade$;

COMMIT;
