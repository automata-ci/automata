ALTER TABLE github_provider_manifest_revisions
    DROP CONSTRAINT github_provider_manifest_revisions_digest_canonical,
    DROP CONSTRAINT github_provider_manifest_revisions_selector_exact;

ALTER TABLE github_provider_manifest_revisions
    ADD COLUMN workflow_selection_kind TEXT COLLATE "C" NOT NULL DEFAULT 'exact',
    ADD CONSTRAINT github_provider_manifest_revisions_selector_exact CHECK (
        event_name = 'push'
        AND git_ref = 'refs/heads/main'
        AND check_subject_key = workflow_path
        AND (
            workflow_selection_kind = 'exact'
            AND workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'
            OR workflow_selection_kind = 'all_direct'
            AND workflow_path = '.ci/workflows'
        )
        AND workflow_path !~ '[[:cntrl:]\\]'
    );

ALTER TABLE github_provider_manifest_revisions
    ALTER COLUMN workflow_selection_kind DROP DEFAULT;

CREATE OR REPLACE FUNCTION automata_github_provider_manifest_digest(
    github_provider_manifest_revisions
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        CASE ($1).workflow_selection_kind
            WHEN 'exact' THEN 'automata.store.github-provider-manifest.v3'
            WHEN 'all_direct' THEN 'automata.store.github-provider-manifest.v4.all-direct'
            ELSE 'invalid'
        END,
        'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).tenant_id, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(($1).repository_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(($1).provider_connection_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).provider_installation_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).github_repository_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_repository_name, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).repository_visibility, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).github_app_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_app_client_id, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_app_jwt_issuer_kind, 'UTF8'))
    || automata_github_provider_manifest_digest_part(($1).app_key_spki_sha256)
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).app_configuration_revision))
    || automata_github_provider_manifest_digest_part(($1).webhook_verifier_fingerprint_sha256)
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).webhook_verifier_revision))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).policy_revision))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).authority_profile, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).runner_policy_object_key, 'UTF8'))
    || automata_github_provider_manifest_digest_part(($1).runner_policy_digest)
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).runner_policy_size_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).runner_policy_media_type, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).runtime_policy_revision))
    || automata_github_provider_manifest_digest_part(($1).runtime_policy_digest)
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).manifest_revision))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).workflow_path, 'UTF8'))
    || CASE WHEN ($1).workflow_selection_kind = 'all_direct'
        THEN automata_github_provider_manifest_digest_part(
            pg_catalog.convert_to(($1).workflow_selection_kind, 'UTF8')
        )
        ELSE ''::BYTEA
       END
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).event_name, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).git_ref, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).check_subject_key, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).check_name, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_web_origin, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_api_origin, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_archive_origin, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_rest_api_version, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_rest_accept, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_archive_accept, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).repository_source_authentication, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).repository_source_revision, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).repository_archive_format, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).webhook_max_body_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).webhook_accept_timeout_ms))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).push_webhook_max_commits))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).path_filter_max_commits))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).path_filter_max_changed_files))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_compressed_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_decompressed_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_entries))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_expanded_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_entry_path_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_workflows))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).workflow_max_bytes))
)
$automata$;

ALTER TABLE github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_digest_canonical CHECK (
        manifest_digest = automata_github_provider_manifest_digest(
            github_provider_manifest_revisions
        )
    );

CREATE TABLE provider_delivery_workflow_inventories (
    inbox_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    manifest_digest BYTEA NOT NULL,
    source_revision TEXT COLLATE "C" NOT NULL,
    repository_source_digest BYTEA NOT NULL,
    inventory_digest BYTEA NOT NULL,
    workflow_count SMALLINT NOT NULL,
    registered_at_ms BIGINT NOT NULL,
    CONSTRAINT provider_delivery_workflow_inventories_tenant_unique
        UNIQUE (tenant_id, inbox_id),
    CONSTRAINT provider_delivery_workflow_inventories_digest_unique
        UNIQUE (tenant_id, inbox_id, inventory_digest),
    CONSTRAINT provider_delivery_workflow_inventories_inbox
        FOREIGN KEY (inbox_id, tenant_id)
        REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT provider_delivery_workflow_inventories_shape CHECK (
        octet_length(manifest_digest) = 32
        AND octet_length(repository_source_digest) = 32
        AND octet_length(inventory_digest) = 32
        AND octet_length(source_revision) BETWEEN 1 AND 1024
        AND btrim(source_revision) = source_revision
        AND source_revision !~ '[[:cntrl:]]'
        AND workflow_count BETWEEN 0 AND 256
        AND registered_at_ms >= 0
    )
);

CREATE TABLE provider_delivery_workflow_inventory_entries (
    inbox_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    ordinal SMALLINT NOT NULL,
    workflow_path TEXT COLLATE "C" NOT NULL,
    source_state TEXT COLLATE "C" NOT NULL,
    source_digest BYTEA,
    CONSTRAINT provider_delivery_workflow_inventory_entries_primary_key
        PRIMARY KEY (inbox_id, workflow_path),
    CONSTRAINT provider_delivery_workflow_inventory_entries_ordinal_unique
        UNIQUE (inbox_id, ordinal),
    CONSTRAINT provider_delivery_workflow_inventory_entries_inventory
        FOREIGN KEY (tenant_id, inbox_id)
        REFERENCES provider_delivery_workflow_inventories(tenant_id, inbox_id)
        ON DELETE RESTRICT,
    CONSTRAINT provider_delivery_workflow_inventory_entries_shape CHECK (
        ordinal BETWEEN 0 AND 255
        AND workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'
        AND workflow_path !~ '[[:cntrl:]\\]'
        AND (
            source_state = 'ready' AND octet_length(source_digest) = 32
            OR source_state IN ('empty', 'oversized', 'missing') AND source_digest IS NULL
        )
    )
);

CREATE TABLE provider_delivery_workflow_progress (
    inbox_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    workflow_path TEXT COLLATE "C" NOT NULL,
    inventory_digest BYTEA NOT NULL,
    outcome_kind TEXT COLLATE "C" NOT NULL,
    run_id UUID,
    failure_kind TEXT COLLATE "C",
    recorded_at_ms BIGINT NOT NULL,
    CONSTRAINT provider_delivery_workflow_progress_primary_key
        PRIMARY KEY (inbox_id, workflow_path),
    CONSTRAINT provider_delivery_workflow_progress_inventory
        FOREIGN KEY (tenant_id, inbox_id, inventory_digest)
        REFERENCES provider_delivery_workflow_inventories(
            tenant_id, inbox_id, inventory_digest
        )
        ON DELETE RESTRICT,
    CONSTRAINT provider_delivery_workflow_progress_entry
        FOREIGN KEY (inbox_id, workflow_path)
        REFERENCES provider_delivery_workflow_inventory_entries(inbox_id, workflow_path)
        ON DELETE RESTRICT,
    CONSTRAINT provider_delivery_workflow_progress_shape CHECK (
        octet_length(inventory_digest) = 32
        AND recorded_at_ms >= 0
        AND (
            outcome_kind = 'admitted' AND run_id IS NOT NULL AND failure_kind IS NULL
            OR outcome_kind IN ('skipped', 'failed') AND run_id IS NULL
                AND octet_length(failure_kind) BETWEEN 1 AND 128
                AND failure_kind ~ '^[a-z0-9](?:[a-z0-9_.:-]*[a-z0-9])?$|^[a-z0-9]$'
        )
    )
);

ALTER TABLE github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_delivery_path_run_unique
        UNIQUE (provider_delivery_id, workflow_path, run_id);

ALTER TABLE provider_delivery_workflow_progress
    ADD CONSTRAINT provider_delivery_workflow_progress_admitted_run_exact
        FOREIGN KEY (inbox_id, workflow_path, run_id)
        REFERENCES github_workflow_run_subject_evidence(
            provider_delivery_id, workflow_path, run_id
        ) ON DELETE RESTRICT;

-- The immutable delivery evidence retains one aggregate Check anchor. In
-- all-direct mode, admission may additionally create one Check for an exact
-- ready inventory entry while the delivery claim is live. Exact mode remains
-- byte-for-byte one-subject authority.
CREATE OR REPLACE FUNCTION automata_github_check_subject_delivery_evidence_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    authority RECORD;
    workflow_authorized BOOLEAN := FALSE;
BEGIN
    SELECT evidence_source.repository_id,
           evidence_source.provider_connection_id,
           evidence_source.provider_installation_id,
           evidence_source.github_repository_id,
           evidence_source.github_repository_name,
           evidence_source.github_check_subject_id,
           evidence_source.github_check_head_sha,
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
     AND manifest_source.provider_connection_id = evidence_source.provider_connection_id
     AND manifest_source.manifest_revision = evidence_source.provider_manifest_revision
     AND manifest_source.manifest_digest = evidence_source.provider_manifest_digest
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

    IF authority.repository_id IS NULL
        OR NEW.repository_id <> authority.repository_id
        OR NEW.provider_connection_id <> authority.provider_connection_id
        OR NEW.provider_installation_id <> authority.provider_installation_id
        OR NEW.github_repository_id <> authority.github_repository_id
        OR NEW.github_repository_name <> authority.github_repository_name
        OR NEW.github_app_id <> authority.github_app_id
        OR NEW.head_sha <> authority.github_check_head_sha
        OR NEW.check_name <> authority.check_name
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
$automata$;

-- Preserve the authenticated-event/repository-dispatch predicates installed
-- by earlier migrations while widening only the subject/path relation. The
-- run receipt remains bound to the exact inventory source digest and manifest.
DO $automata$
DECLARE
    current_definition TEXT;
    patched_definition TEXT;
    selection_projection CONSTANT TEXT :=
        '           manifest_source.workflow_path AS manifest_workflow_path,' || chr(10) ||
        '           manifest_source.event_name AS manifest_event_name,';
    subject_join CONSTANT TEXT :=
        '    JOIN github_check_subjects AS subject_source' || chr(10) ||
        '      ON subject_source.id = evidence_source.github_check_subject_id' || chr(10) ||
        '     AND subject_source.tenant_id = evidence_source.tenant_id';
    anchor_guard CONSTANT TEXT :=
        '        OR NEW.github_check_subject_id <> source_evidence.github_check_subject_id' ||
        chr(10);
    workflow_guard CONSTANT TEXT :=
        '        OR source_evidence.subject_key <> source_evidence.manifest_workflow_path' ||
        chr(10) ||
        '        OR NEW.workflow_path <> source_evidence.manifest_workflow_path';
BEGIN
    SELECT pg_get_functiondef(
        'automata_github_workflow_run_subject_evidence_insert_guard()'::REGPROCEDURE
    ) INTO current_definition;

    IF strpos(current_definition, selection_projection) = 0
        OR strpos(current_definition, subject_join) = 0
        OR strpos(current_definition, anchor_guard) = 0
        OR strpos(current_definition, workflow_guard) = 0
        OR strpos(
            current_definition,
            'COALESCE(source_evidence.authenticated_event_name, source_evidence.manifest_event_name)'
        ) = 0
        OR strpos(
            current_definition,
            'COALESCE(source_evidence.authenticated_event_git_ref, source_evidence.manifest_git_ref)'
        ) = 0
    THEN
        RAISE EXCEPTION 'unexpected GitHub run-subject evidence guard definition'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_run_subject_evidence_guard_upgrade_exact';
    END IF;

    patched_definition := replace(
        current_definition,
        selection_projection,
        '           manifest_source.workflow_path AS manifest_workflow_path,' || chr(10) ||
        '           manifest_source.workflow_selection_kind AS manifest_workflow_selection_kind,' || chr(10) ||
        '           manifest_source.event_name AS manifest_event_name,'
    );
    patched_definition := replace(
        patched_definition,
        subject_join,
        '    JOIN github_check_subjects AS subject_source' || chr(10) ||
        '      ON subject_source.id = NEW.github_check_subject_id' || chr(10) ||
        '     AND subject_source.tenant_id = evidence_source.tenant_id' || chr(10) ||
        '     AND subject_source.provider_delivery_id = evidence_source.provider_delivery_id' || chr(10) ||
        '     AND subject_source.repository_id = evidence_source.repository_id'
    );
    patched_definition := replace(patched_definition, anchor_guard, '');
    patched_definition := replace(
        patched_definition,
        workflow_guard,
        '        OR source_evidence.subject_key <> NEW.workflow_path' || chr(10) ||
        '        OR NOT (' || chr(10) ||
        '            source_evidence.manifest_workflow_selection_kind = ''exact''' || chr(10) ||
        '            AND NEW.github_check_subject_id = source_evidence.github_check_subject_id' || chr(10) ||
        '            AND NEW.workflow_path = source_evidence.manifest_workflow_path' || chr(10) ||
        '            OR source_evidence.manifest_workflow_selection_kind = ''all_direct''' || chr(10) ||
        '            AND EXISTS (' || chr(10) ||
        '                SELECT 1' || chr(10) ||
        '                FROM provider_delivery_workflow_inventories AS inventory' || chr(10) ||
        '                JOIN provider_delivery_workflow_inventory_entries AS entry' || chr(10) ||
        '                  ON entry.inbox_id = inventory.inbox_id' || chr(10) ||
        '                 AND entry.tenant_id = inventory.tenant_id' || chr(10) ||
        '                WHERE inventory.inbox_id = NEW.provider_delivery_id' || chr(10) ||
        '                  AND inventory.tenant_id = NEW.tenant_id' || chr(10) ||
        '                  AND inventory.manifest_digest =' || chr(10) ||
        '                      source_evidence.provider_manifest_digest' || chr(10) ||
        '                  AND entry.workflow_path = NEW.workflow_path' || chr(10) ||
        '                  AND entry.source_state = ''ready''' || chr(10) ||
        '                  AND entry.source_digest = NEW.source_digest' || chr(10) ||
        '            )' || chr(10) ||
        '        )'
    );

    IF patched_definition = current_definition
        OR strpos(patched_definition, selection_projection) > 0
        OR strpos(patched_definition, subject_join) > 0
        OR strpos(patched_definition, workflow_guard) > 0
    THEN
        RAISE EXCEPTION 'GitHub run-subject evidence guard upgrade was incomplete'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_run_subject_evidence_guard_upgrade_exact';
    END IF;

    EXECUTE patched_definition;
END;
$automata$;

CREATE FUNCTION automata_provider_delivery_workflow_inventory_part(BYTEA)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.int8send(pg_catalog.octet_length($1)::BIGINT) || $1
$automata$;

CREATE FUNCTION automata_provider_delivery_workflow_inventory_digest(UUID)
RETURNS BYTEA
LANGUAGE SQL
STABLE
STRICT
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.provider-delivery-workflow-inventory.v1', 'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || inventory.manifest_digest
    || automata_provider_delivery_workflow_inventory_part(
        pg_catalog.convert_to(inventory.source_revision, 'UTF8')
    )
    || inventory.repository_source_digest
    || pg_catalog.int8send(inventory.workflow_count::BIGINT)
    || coalesce((
        SELECT string_agg(
            automata_provider_delivery_workflow_inventory_part(
                pg_catalog.convert_to(entry.workflow_path, 'UTF8')
            )
            || automata_provider_delivery_workflow_inventory_part(
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
$automata$;

CREATE FUNCTION automata_guard_provider_delivery_workflow_inventory()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    inbox provider_delivery_inbox%ROWTYPE;
    manifest_digest BYTEA;
BEGIN
    SELECT * INTO inbox
    FROM provider_delivery_inbox
    WHERE id = NEW.inbox_id AND tenant_id = NEW.tenant_id
    FOR SHARE;
    SELECT evidence.provider_manifest_digest INTO manifest_digest
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
    THEN
        RAISE EXCEPTION 'provider delivery workflow inventory lacks live authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_inventory_live_authority';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER provider_delivery_workflow_inventories_00_insert_guard
BEFORE INSERT ON provider_delivery_workflow_inventories
FOR EACH ROW EXECUTE FUNCTION automata_guard_provider_delivery_workflow_inventory();

CREATE FUNCTION automata_guard_provider_delivery_workflow_inventory_entry()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    inbox_state TEXT;
BEGIN
    SELECT inbox.state INTO inbox_state
    FROM provider_delivery_inbox AS inbox
    JOIN provider_delivery_workflow_inventories AS inventory
      ON inventory.inbox_id = inbox.id
     AND inventory.tenant_id = inbox.tenant_id
    WHERE inventory.inbox_id = NEW.inbox_id
      AND inventory.tenant_id = NEW.tenant_id
    FOR SHARE OF inbox, inventory;
    IF inbox_state IS DISTINCT FROM 'claimed' THEN
        RAISE EXCEPTION 'provider delivery workflow inventory entry lacks live authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_inventory_entry_live_authority';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER provider_delivery_workflow_inventory_entries_00_insert_guard
BEFORE INSERT ON provider_delivery_workflow_inventory_entries
FOR EACH ROW EXECUTE FUNCTION automata_guard_provider_delivery_workflow_inventory_entry();

CREATE FUNCTION automata_guard_provider_delivery_workflow_progress()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    inbox_row provider_delivery_inbox%ROWTYPE;
BEGIN
    SELECT inbox_source.* INTO inbox_row
    FROM provider_delivery_inbox AS inbox_source
    JOIN provider_delivery_workflow_inventories AS inventory
      ON inventory.inbox_id = inbox_source.id
     AND inventory.tenant_id = inbox_source.tenant_id
     AND inventory.inventory_digest = NEW.inventory_digest
    WHERE inventory.inbox_id = NEW.inbox_id
      AND inventory.tenant_id = NEW.tenant_id
    FOR SHARE OF inbox_source, inventory;
    IF inbox_row.id IS NULL
        OR inbox_row.state <> 'claimed'
        OR NEW.recorded_at_ms < inbox_row.claimed_at_ms
        OR NEW.recorded_at_ms >= inbox_row.claim_expires_at_ms
    THEN
        RAISE EXCEPTION 'provider delivery workflow progress lacks live authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_progress_live_authority';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER provider_delivery_workflow_progress_00_insert_guard
BEFORE INSERT ON provider_delivery_workflow_progress
FOR EACH ROW EXECUTE FUNCTION automata_guard_provider_delivery_workflow_progress();

CREATE FUNCTION automata_verify_provider_delivery_workflow_inventory()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE CONSTRAINT TRIGGER provider_delivery_workflow_inventories_digest_canonical
AFTER INSERT ON provider_delivery_workflow_inventories
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_verify_provider_delivery_workflow_inventory();
CREATE CONSTRAINT TRIGGER provider_delivery_workflow_inventory_entries_digest_canonical
AFTER INSERT ON provider_delivery_workflow_inventory_entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_verify_provider_delivery_workflow_inventory();

CREATE FUNCTION automata_reject_provider_delivery_workflow_progress_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'provider delivery workflow progress is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'provider_delivery_workflow_progress_immutable';
END;
$automata$;

CREATE TRIGGER provider_delivery_workflow_inventories_no_mutation
BEFORE UPDATE OR DELETE ON provider_delivery_workflow_inventories
FOR EACH ROW EXECUTE FUNCTION automata_reject_provider_delivery_workflow_progress_mutation();
CREATE TRIGGER provider_delivery_workflow_inventory_entries_no_mutation
BEFORE UPDATE OR DELETE ON provider_delivery_workflow_inventory_entries
FOR EACH ROW EXECUTE FUNCTION automata_reject_provider_delivery_workflow_progress_mutation();
CREATE TRIGGER provider_delivery_workflow_progress_no_mutation
BEFORE UPDATE OR DELETE ON provider_delivery_workflow_progress
FOR EACH ROW EXECUTE FUNCTION automata_reject_provider_delivery_workflow_progress_mutation();

CREATE TRIGGER provider_delivery_workflow_inventories_no_truncate
BEFORE TRUNCATE ON provider_delivery_workflow_inventories
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_provider_delivery_workflow_progress_mutation();
CREATE TRIGGER provider_delivery_workflow_inventory_entries_no_truncate
BEFORE TRUNCATE ON provider_delivery_workflow_inventory_entries
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_provider_delivery_workflow_progress_mutation();
CREATE TRIGGER provider_delivery_workflow_progress_no_truncate
BEFORE TRUNCATE ON provider_delivery_workflow_progress
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_provider_delivery_workflow_progress_mutation();

CREATE FUNCTION automata_require_provider_delivery_workflow_progress_completion()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    requires_inventory BOOLEAN;
    inventory_count INTEGER;
    entry_count INTEGER;
    progress_count INTEGER;
    outcome_count INTEGER;
BEGIN
    IF NEW.state <> 'completed' OR OLD.state = 'completed' THEN
        RETURN NEW;
    END IF;

    SELECT manifest.workflow_selection_kind = 'all_direct'
      INTO requires_inventory
    FROM github_provider_delivery_evidence AS evidence
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = evidence.tenant_id
     AND manifest.repository_id = evidence.repository_id
     AND manifest.provider_connection_id = evidence.provider_connection_id
     AND manifest.manifest_revision = evidence.provider_manifest_revision
     AND manifest.manifest_digest = evidence.provider_manifest_digest
    WHERE evidence.provider_delivery_id = NEW.id;

    IF requires_inventory IS DISTINCT FROM TRUE
       AND NOT EXISTS (
           SELECT 1 FROM provider_delivery_workflow_inventories
           WHERE inbox_id = NEW.id
       )
    THEN
        RETURN NEW;
    END IF;

    SELECT inventory.workflow_count,
           (SELECT count(*) FROM provider_delivery_workflow_inventory_entries AS entry
             WHERE entry.inbox_id = NEW.id),
           (SELECT count(*) FROM provider_delivery_workflow_progress AS progress
             WHERE progress.inbox_id = NEW.id),
           (SELECT count(*) FROM provider_delivery_workflow_outcomes AS outcome
             WHERE outcome.inbox_id = NEW.id)
      INTO inventory_count, entry_count, progress_count, outcome_count
    FROM provider_delivery_workflow_inventories AS inventory
    WHERE inventory.inbox_id = NEW.id;

    IF NOT FOUND
        OR inventory_count <> entry_count
        OR inventory_count <> progress_count
        OR inventory_count <> outcome_count
        OR EXISTS (
            SELECT 1
            FROM provider_delivery_workflow_progress AS progress
            FULL JOIN provider_delivery_workflow_outcomes AS outcome
              ON outcome.inbox_id = progress.inbox_id
             AND outcome.workflow_path = progress.workflow_path
            WHERE coalesce(progress.inbox_id, outcome.inbox_id) = NEW.id
              AND (
                  progress.workflow_path IS NULL OR outcome.workflow_path IS NULL
                  OR progress.outcome_kind <> outcome.outcome_kind
                  OR progress.run_id IS DISTINCT FROM outcome.run_id
                  OR progress.failure_kind IS DISTINCT FROM outcome.failure_kind
              )
        )
    THEN
        RAISE EXCEPTION 'provider delivery completion does not match durable workflow progress'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_progress_completion_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE CONSTRAINT TRIGGER provider_delivery_inbox_workflow_progress_completion
AFTER UPDATE OF state ON provider_delivery_inbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_provider_delivery_workflow_progress_completion();
