-- EVT-01/AUTH-02: additive generalized event admission and trust prerequisites.
--
-- The original EVT-01 implementation evolved a monolithic development baseline.
-- This migration carries those contracts forward without modifying frozen history.

ALTER TABLE github_provider_manifest_revisions
    ADD COLUMN installation_binding_generation BIGINT NOT NULL DEFAULT 1;

ALTER TABLE github_provider_manifest_revisions
    ALTER COLUMN installation_binding_generation DROP DEFAULT;

ALTER TABLE github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_installation_binding_generation_positive
        CHECK (installation_binding_generation > 0);

CREATE OR REPLACE FUNCTION automata_github_provider_manifest_digest(github_provider_manifest_revisions) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.github-provider-manifest', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).tenant_id, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(($1).repository_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(($1).provider_connection_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).provider_installation_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).installation_binding_generation))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).github_repository_id))
    || CASE WHEN ($1).github_repository_owner_id IS NULL
        THEN ''::BYTEA
        ELSE automata_github_provider_manifest_digest_part(
            pg_catalog.int8send(($1).github_repository_owner_id)
        )
       END
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
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).workflow_selection_kind, 'UTF8')
    )
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
$_$;

CREATE OR REPLACE FUNCTION automata_github_provider_manifest_current_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    prior github_provider_manifest_revisions%ROWTYPE;
    replacement github_provider_manifest_revisions%ROWTYPE;
    installation_changed BOOLEAN;
    app_evidence_changed BOOLEAN;
    verifier_evidence_changed BOOLEAN;
    policy_evidence_changed BOOLEAN;
    runtime_policy_changed BOOLEAN;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'GitHub provider manifest current pointers cannot be removed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_current_removal_forbidden';
    END IF;

    IF TG_OP = 'INSERT' THEN
        SELECT * INTO STRICT replacement
        FROM github_provider_manifest_revisions
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND provider_connection_id = NEW.provider_connection_id
          AND manifest_revision = NEW.manifest_revision
          AND manifest_digest = NEW.manifest_digest;
        IF NEW.manifest_revision <> 1 THEN
            RAISE EXCEPTION 'initial GitHub provider manifest revision must be one'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_provider_manifest_current_initial_revision';
        ELSIF replacement.installation_binding_generation <> 1 THEN
            RAISE EXCEPTION 'initial GitHub installation binding generation must be one'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_provider_manifest_current_initial_installation_binding';
        ELSIF NEW.activated_at_ms <> replacement.registered_at_ms THEN
            RAISE EXCEPTION 'GitHub provider manifest activation must equal registration'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_provider_manifest_current_time';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR OLD.manifest_revision = 9223372036854775807
        OR NEW.manifest_revision <> OLD.manifest_revision + 1
        OR NEW.manifest_digest IS NOT DISTINCT FROM OLD.manifest_digest
        OR NEW.activated_at_ms < OLD.activated_at_ms
    THEN
        RAISE EXCEPTION 'GitHub provider manifest current transition is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_current_transition';
    END IF;

    SELECT * INTO STRICT prior
    FROM github_provider_manifest_revisions
    WHERE tenant_id = OLD.tenant_id
      AND repository_id = OLD.repository_id
      AND provider_connection_id = OLD.provider_connection_id
      AND manifest_revision = OLD.manifest_revision
      AND manifest_digest = OLD.manifest_digest;
    SELECT * INTO STRICT replacement
    FROM github_provider_manifest_revisions
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND provider_connection_id = NEW.provider_connection_id
      AND manifest_revision = NEW.manifest_revision
      AND manifest_digest = NEW.manifest_digest;

    IF NEW.activated_at_ms <> replacement.registered_at_ms THEN
        RAISE EXCEPTION 'GitHub provider manifest activation must equal registration'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_current_time';
    END IF;
    IF replacement.repository_id IS DISTINCT FROM prior.repository_id
        OR replacement.github_repository_id IS DISTINCT FROM prior.github_repository_id
        OR replacement.github_repository_name IS DISTINCT FROM prior.github_repository_name
        OR replacement.github_app_id IS DISTINCT FROM prior.github_app_id
        OR replacement.github_app_client_id IS DISTINCT FROM prior.github_app_client_id
        OR replacement.github_app_jwt_issuer_kind IS DISTINCT FROM prior.github_app_jwt_issuer_kind
        OR replacement.github_web_origin IS DISTINCT FROM prior.github_web_origin
        OR replacement.github_api_origin IS DISTINCT FROM prior.github_api_origin
        OR replacement.github_archive_origin IS DISTINCT FROM prior.github_archive_origin
    THEN
        RAISE EXCEPTION 'GitHub provider manifest connection identity changed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_connection_immutable';
    END IF;

    installation_changed = replacement.provider_installation_id
        IS DISTINCT FROM prior.provider_installation_id;
    app_evidence_changed = replacement.app_key_spki_sha256
        IS DISTINCT FROM prior.app_key_spki_sha256;
    verifier_evidence_changed = replacement.webhook_verifier_fingerprint_sha256
        IS DISTINCT FROM prior.webhook_verifier_fingerprint_sha256;
    runtime_policy_changed = replacement.runtime_policy_digest
        IS DISTINCT FROM prior.runtime_policy_digest;
    policy_evidence_changed =
        replacement.policy_revision IS DISTINCT FROM prior.policy_revision
        OR replacement.repository_visibility IS DISTINCT FROM prior.repository_visibility
        OR replacement.github_repository_owner_id IS DISTINCT FROM prior.github_repository_owner_id
        OR replacement.authority_profile IS DISTINCT FROM prior.authority_profile
        OR replacement.runner_policy_digest IS DISTINCT FROM prior.runner_policy_digest
        OR replacement.runner_policy_object_key IS DISTINCT FROM prior.runner_policy_object_key
        OR replacement.runner_policy_size_bytes IS DISTINCT FROM prior.runner_policy_size_bytes
        OR replacement.runner_policy_media_type IS DISTINCT FROM prior.runner_policy_media_type
        OR runtime_policy_changed
        OR replacement.workflow_path IS DISTINCT FROM prior.workflow_path
        OR replacement.event_name IS DISTINCT FROM prior.event_name
        OR replacement.git_ref IS DISTINCT FROM prior.git_ref
        OR replacement.check_subject_key IS DISTINCT FROM prior.check_subject_key
        OR replacement.check_name IS DISTINCT FROM prior.check_name
        OR replacement.github_rest_api_version IS DISTINCT FROM prior.github_rest_api_version
        OR replacement.github_rest_accept IS DISTINCT FROM prior.github_rest_accept
        OR replacement.github_archive_accept IS DISTINCT FROM prior.github_archive_accept
        OR replacement.repository_source_authentication IS DISTINCT FROM prior.repository_source_authentication
        OR replacement.repository_source_revision IS DISTINCT FROM prior.repository_source_revision
        OR replacement.repository_archive_format IS DISTINCT FROM prior.repository_archive_format
        OR replacement.webhook_max_body_bytes IS DISTINCT FROM prior.webhook_max_body_bytes
        OR replacement.webhook_accept_timeout_ms IS DISTINCT FROM prior.webhook_accept_timeout_ms
        OR replacement.push_webhook_max_commits IS DISTINCT FROM prior.push_webhook_max_commits
        OR replacement.path_filter_max_commits IS DISTINCT FROM prior.path_filter_max_commits
        OR replacement.path_filter_max_changed_files IS DISTINCT FROM prior.path_filter_max_changed_files
        OR replacement.archive_max_compressed_bytes IS DISTINCT FROM prior.archive_max_compressed_bytes
        OR replacement.archive_max_decompressed_bytes IS DISTINCT FROM prior.archive_max_decompressed_bytes
        OR replacement.archive_max_entries IS DISTINCT FROM prior.archive_max_entries
        OR replacement.archive_max_expanded_bytes IS DISTINCT FROM prior.archive_max_expanded_bytes
        OR replacement.archive_max_entry_path_bytes IS DISTINCT FROM prior.archive_max_entry_path_bytes
        OR replacement.archive_max_workflows IS DISTINCT FROM prior.archive_max_workflows
        OR replacement.workflow_max_bytes IS DISTINCT FROM prior.workflow_max_bytes;

    IF NOT (
        installation_changed
        OR app_evidence_changed
        OR verifier_evidence_changed
        OR policy_evidence_changed
    )
        OR (CASE WHEN installation_changed THEN
            prior.installation_binding_generation = 9223372036854775807
            OR replacement.installation_binding_generation
                <> prior.installation_binding_generation + 1
          ELSE replacement.installation_binding_generation
                <> prior.installation_binding_generation END)
        OR (CASE WHEN app_evidence_changed THEN
            prior.app_configuration_revision = 9223372036854775807
            OR replacement.app_configuration_revision <> prior.app_configuration_revision + 1
          ELSE replacement.app_configuration_revision <> prior.app_configuration_revision END)
        OR (CASE WHEN verifier_evidence_changed THEN
            prior.webhook_verifier_revision = 9223372036854775807
            OR replacement.webhook_verifier_revision <> prior.webhook_verifier_revision + 1
          ELSE replacement.webhook_verifier_revision <> prior.webhook_verifier_revision END)
        OR (CASE WHEN policy_evidence_changed THEN
            prior.policy_revision = 9223372036854775807
            OR replacement.policy_revision <> prior.policy_revision + 1
          ELSE replacement.policy_revision <> prior.policy_revision END)
        OR (CASE WHEN runtime_policy_changed THEN
            prior.runtime_policy_revision = 9223372036854775807
            OR replacement.runtime_policy_revision <> prior.runtime_policy_revision + 1
          ELSE replacement.runtime_policy_revision <> prior.runtime_policy_revision END)
    THEN
        RAISE EXCEPTION 'GitHub provider manifest policy revision did not advance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_revision_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION automata_guard_provider_delivery_workflow_inventory() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    inbox provider_delivery_inbox%ROWTYPE;
    manifest_digest BYTEA;
    authenticated_source_revision TEXT;
BEGIN
    SELECT * INTO inbox
    FROM provider_delivery_inbox
    WHERE id = NEW.inbox_id AND tenant_id = NEW.tenant_id
    FOR SHARE;
    SELECT evidence.provider_manifest_digest,
           pg_catalog.encode(evidence.github_check_head_sha, 'hex')
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
$$;

CREATE FUNCTION automata_event_subject_digest_part(bytea) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
SELECT pg_catalog.int8send(pg_catalog.octet_length($1)::BIGINT) || $1
$_$;

CREATE FUNCTION automata_event_subject_origin_registry_digest() RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $_$
SELECT pg_catalog.decode(
    '9a4db79fca7f5bb52f77039e066f291d9659e57bf3a557fa213db8fb9d85ee5d',
    'hex'
)
$_$;

CREATE FUNCTION automata_event_subject_id(text, uuid, smallint, uuid, text) RETURNS uuid
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
WITH raw(bytes) AS (
    SELECT substring(
        pg_catalog.sha256(
            pg_catalog.convert_to('automata.store.event-subject-id.v1', 'UTF8')
            || pg_catalog.decode('00', 'hex')
            || automata_event_subject_digest_part(pg_catalog.convert_to($1, 'UTF8'))
            || pg_catalog.uuid_send($2)
            || pg_catalog.int2send($3)
            || pg_catalog.uuid_send($4)
            || automata_event_subject_digest_part(pg_catalog.convert_to($5, 'UTF8'))
        )
        FROM 1 FOR 16
    )
), shaped(bytes) AS (
    SELECT pg_catalog.set_byte(
        pg_catalog.set_byte(bytes, 6, (pg_catalog.get_byte(bytes, 6) & 15) | 128),
        8,
        (pg_catalog.get_byte(bytes, 8) & 63) | 128
    )
    FROM raw
), encoded(hex) AS (
    SELECT pg_catalog.encode(bytes, 'hex') FROM shaped
)
SELECT (
    substring(hex FROM 1 FOR 8) || '-' ||
    substring(hex FROM 9 FOR 4) || '-' ||
    substring(hex FROM 13 FOR 4) || '-' ||
    substring(hex FROM 17 FOR 4) || '-' ||
    substring(hex FROM 21 FOR 12)
)::UUID
FROM encoded
$_$;

CREATE FUNCTION automata_event_control_subject_id(uuid) RETURNS uuid
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
WITH raw(bytes) AS (
    SELECT substring(
        pg_catalog.sha256(
            pg_catalog.convert_to('automata.store.event-control-subject-id.v1', 'UTF8')
            || pg_catalog.decode('00', 'hex')
            || pg_catalog.uuid_send($1)
        )
        FROM 1 FOR 16
    )
), shaped(bytes) AS (
    SELECT pg_catalog.set_byte(
        pg_catalog.set_byte(bytes, 6, (pg_catalog.get_byte(bytes, 6) & 15) | 128),
        8,
        (pg_catalog.get_byte(bytes, 8) & 63) | 128
    )
    FROM raw
), encoded(hex) AS (
    SELECT pg_catalog.encode(bytes, 'hex') FROM shaped
)
SELECT (
    substring(hex FROM 1 FOR 8) || '-' ||
    substring(hex FROM 9 FOR 4) || '-' ||
    substring(hex FROM 13 FOR 4) || '-' ||
    substring(hex FROM 17 FOR 4) || '-' ||
    substring(hex FROM 21 FOR 12)
)::UUID
FROM encoded
$_$;

CREATE FUNCTION automata_event_subject_selection_digest(
    smallint, smallint, bytea, uuid, text, uuid, smallint, uuid,
    text, text, text, bytea, bytea, bigint
) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
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
    || automata_event_subject_digest_part(pg_catalog.convert_to($11, 'UTF8'))
    || $12
    || $13
    || pg_catalog.int8send($14)
)
$_$;

CREATE FUNCTION automata_event_control_subject_digest(
    smallint, uuid, uuid, bytea, bigint
) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.event-control-subject.v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || pg_catalog.int2send($1)
    || pg_catalog.uuid_send($2)
    || pg_catalog.uuid_send($3)
    || $4
    || pg_catalog.int8send($5)
)
$_$;

CREATE FUNCTION automata_event_subject_progress_digest(
    smallint, uuid, bytea, text, uuid, text, bigint
) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $_$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.event-subject-progress.v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || pg_catalog.int2send($1)
    || pg_catalog.uuid_send($2)
    || $3
    || automata_event_subject_digest_part(pg_catalog.convert_to($4, 'UTF8'))
    || CASE WHEN $5 IS NULL THEN ''::BYTEA ELSE pg_catalog.uuid_send($5) END
    || CASE WHEN $6 IS NULL THEN ''::BYTEA
            ELSE automata_event_subject_digest_part(pg_catalog.convert_to($6, 'UTF8')) END
    || pg_catalog.int8send($7)
)
$_$;

CREATE FUNCTION automata_event_subject_records_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'event-subject durable records are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'event_subject_records_immutable';
END;
$$;

CREATE FUNCTION automata_event_control_subject_timeline_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM 1
    FROM event_subject_selections AS selection
    WHERE selection.tenant_id = NEW.tenant_id
      AND selection.subject_id = NEW.subject_id
      AND selection.selection_digest = NEW.selection_digest
      AND NEW.registered_at_ms >= selection.selected_at_ms;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'event control registration precedes its immutable selection'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'event_control_subjects_timeline_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_event_subject_progress_insert_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
      AND pg_catalog.encode(run.head_sha, 'hex') = selection.source_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'admitted event-subject progress does not match its selected workflow run'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'event_subject_progress_admitted_run_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE event_subject_selections (
    subject_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    selection_schema smallint NOT NULL,
    origin_registry_version smallint NOT NULL,
    origin_registry_digest bytea NOT NULL,
    origin_kind_code smallint NOT NULL,
    origin_kind_name text NOT NULL COLLATE pg_catalog."C",
    origin_id uuid NOT NULL,
    event_name text NOT NULL COLLATE pg_catalog."C",
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    source_revision text NOT NULL COLLATE pg_catalog."C",
    source_digest bytea NOT NULL,
    authority_digest bytea NOT NULL,
    selected_at_ms bigint NOT NULL,
    selection_digest bytea NOT NULL,
    CONSTRAINT event_subject_selections_registry_exact CHECK ((
        origin_registry_version = 1
        AND origin_registry_digest = automata_event_subject_origin_registry_digest()
    )),
    CONSTRAINT event_subject_selections_origin_exact CHECK ((
        (origin_kind_code = 1 AND origin_kind_name = 'provider_delivery')
        OR (origin_kind_code = 2 AND origin_kind_name = 'schedule_fire')
        OR (origin_kind_code = 3 AND origin_kind_name = 'manual_operation')
        OR (origin_kind_code = 4 AND origin_kind_name = 'workflow_run')
    )),
    CONSTRAINT event_subject_selections_shape CHECK ((
        subject_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND origin_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND selection_schema = 1
        AND octet_length(origin_registry_digest) = 32
        AND octet_length(source_digest) = 32
        AND octet_length(authority_digest) = 32
        AND octet_length(selection_digest) = 32
        AND selected_at_ms >= 0
        AND octet_length(event_name) BETWEEN 1 AND 128
        AND event_name ~ '^[a-z][a-z0-9._-]*$'
        AND octet_length(workflow_path) BETWEEN 1 AND 1024
        AND btrim(workflow_path) = workflow_path
        AND workflow_path !~ '[[:cntrl:]\\]'
        AND left(workflow_path, 1) <> '/'
        AND workflow_path !~ '(^|/)(\.|\.\.)(/|$)'
        AND workflow_path !~ '//'
        AND octet_length(source_revision) BETWEEN 1 AND 1024
        AND btrim(source_revision) = source_revision
        AND source_revision !~ '[[:cntrl:]]'
    )),
    CONSTRAINT event_subject_selections_id_canonical CHECK ((
        subject_id = automata_event_subject_id(
            tenant_id, repository_id, origin_kind_code, origin_id, workflow_path
        )
    )),
    CONSTRAINT event_subject_selections_digest_canonical CHECK ((
        selection_digest = automata_event_subject_selection_digest(
            selection_schema, origin_registry_version, origin_registry_digest,
            subject_id, tenant_id, repository_id, origin_kind_code, origin_id,
            event_name, workflow_path, source_revision, source_digest,
            authority_digest, selected_at_ms
        )
    )),
    UNIQUE (tenant_id, subject_id, selection_digest),
    UNIQUE (tenant_id, repository_id, origin_kind_code, origin_id, workflow_path)
);

CREATE TABLE event_control_subjects (
    control_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    subject_id uuid NOT NULL UNIQUE,
    control_schema smallint NOT NULL,
    selection_digest bytea NOT NULL,
    registered_at_ms bigint NOT NULL,
    control_digest bytea NOT NULL,
    CONSTRAINT event_control_subjects_shape CHECK ((
        control_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND subject_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND control_schema = 1
        AND octet_length(selection_digest) = 32
        AND octet_length(control_digest) = 32
        AND registered_at_ms >= 0
    )),
    CONSTRAINT event_control_subjects_id_canonical CHECK ((
        control_id = automata_event_control_subject_id(subject_id)
    )),
    CONSTRAINT event_control_subjects_digest_canonical CHECK ((
        control_digest = automata_event_control_subject_digest(
            control_schema, control_id, subject_id, selection_digest, registered_at_ms
        )
    )),
    FOREIGN KEY (tenant_id, subject_id, selection_digest)
        REFERENCES event_subject_selections(tenant_id, subject_id, selection_digest)
        ON DELETE RESTRICT
);

CREATE TABLE event_subject_progress (
    subject_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    progress_schema smallint NOT NULL,
    selection_digest bytea NOT NULL,
    outcome_kind text NOT NULL COLLATE pg_catalog."C",
    run_id uuid,
    reason text COLLATE pg_catalog."C",
    recorded_at_ms bigint NOT NULL,
    progress_digest bytea NOT NULL,
    CONSTRAINT event_subject_progress_shape CHECK ((
        subject_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND progress_schema = 1
        AND octet_length(selection_digest) = 32
        AND octet_length(progress_digest) = 32
        AND recorded_at_ms >= 0
        AND (
            (outcome_kind = 'admitted' AND run_id IS NOT NULL
                AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
                AND reason IS NULL)
            OR (outcome_kind IN ('skipped', 'failed') AND run_id IS NULL
                AND reason IS NOT NULL
                AND octet_length(reason) BETWEEN 1 AND 128
                AND reason ~ '^[a-z][a-z0-9._-]*$')
        )
    )),
    CONSTRAINT event_subject_progress_digest_canonical CHECK ((
        progress_digest = automata_event_subject_progress_digest(
            progress_schema, subject_id, selection_digest, outcome_kind,
            run_id, reason, recorded_at_ms
        )
    )),
    FOREIGN KEY (tenant_id, subject_id, selection_digest)
        REFERENCES event_subject_selections(tenant_id, subject_id, selection_digest)
        ON DELETE RESTRICT
);

CREATE FUNCTION automata_require_event_subject_control() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM event_control_subjects AS control
         WHERE control.tenant_id = NEW.tenant_id
           AND control.subject_id = NEW.subject_id
           AND control.control_id = automata_event_control_subject_id(NEW.subject_id)
           AND control.selection_digest = NEW.selection_digest
    ) THEN
        RAISE EXCEPTION 'event selection must register its canonical control atomically'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'event_subject_selection_control_required';
    END IF;
    RETURN NULL;
END;
$$;

ALTER TABLE workflow_definitions
    ADD CONSTRAINT workflow_definitions_repository_id_path_unique
        UNIQUE (repository_id, id, path);

CREATE TABLE workflow_enable_state_revisions (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    state_revision bigint NOT NULL,
    enable_state text NOT NULL COLLATE pg_catalog."C",
    changed_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, workflow_id, state_revision),
    CONSTRAINT workflow_enable_state_revisions_identity CHECK ((repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT workflow_enable_state_revisions_path CHECK ((((octet_length(workflow_path) >= 1) AND (octet_length(workflow_path) <= 1024)) AND (btrim(workflow_path) = workflow_path) AND (workflow_path !~ '[[:cntrl:]\\]'::text) AND ("left"(workflow_path, 1) <> '/'::text) AND (workflow_path !~ '(^|/)(\.|\.\.)(/|$)'::text) AND (workflow_path !~ '//'::text))),
    CONSTRAINT workflow_enable_state_revisions_shape CHECK ((state_revision > 0) AND (enable_state = ANY (ARRAY['enabled'::text, 'disabled'::text])) AND (changed_at_ms >= 0)),
    UNIQUE (repository_id, workflow_id, state_revision),
    UNIQUE (repository_id, workflow_id, workflow_path, state_revision)
);

CREATE TABLE workflow_enable_state_current (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    state_revision bigint NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, workflow_id),
    FOREIGN KEY (tenant_id, repository_id, workflow_id, state_revision)
        REFERENCES workflow_enable_state_revisions(tenant_id, repository_id, workflow_id, state_revision)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_enable_state_current_shape CHECK ((repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (state_revision > 0))
);

CREATE FUNCTION automata_workflow_enable_state_revision_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow enable-state revisions are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workflow_enable_state_revisions_immutable';
END;
$$;

CREATE FUNCTION automata_workflow_enable_state_revision_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_revision workflow_enable_state_revisions%ROWTYPE;
BEGIN
    SELECT revision.* INTO current_revision
    FROM workflow_enable_state_current AS current
    JOIN workflow_enable_state_revisions AS revision
      ON revision.tenant_id = current.tenant_id
     AND revision.repository_id = current.repository_id
     AND revision.workflow_id = current.workflow_id
     AND revision.state_revision = current.state_revision
    WHERE current.tenant_id = NEW.tenant_id
      AND current.repository_id = NEW.repository_id
      AND current.workflow_id = NEW.workflow_id
    FOR SHARE OF current;

    IF NOT FOUND THEN
        IF NEW.state_revision <> 1
            OR EXISTS (
                SELECT 1
                FROM workflow_enable_state_revisions AS history
                WHERE history.tenant_id = NEW.tenant_id
                  AND history.repository_id = NEW.repository_id
                  AND history.workflow_id = NEW.workflow_id
            )
        THEN
            RAISE EXCEPTION 'workflow enable-state history must begin at revision one'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'workflow_enable_state_revisions_contiguous';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.state_revision <> current_revision.state_revision + 1
        OR NEW.workflow_path IS DISTINCT FROM current_revision.workflow_path
        OR NEW.enable_state IS NOT DISTINCT FROM current_revision.enable_state
        OR NEW.changed_at_ms < current_revision.changed_at_ms
    THEN
        RAISE EXCEPTION 'workflow enable-state successor is not exact and contiguous'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_enable_state_revisions_contiguous';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_workflow_enable_state_current_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'workflow enable-state current pointers cannot be removed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_enable_state_current_immutable';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.state_revision <> 1
            OR NOT EXISTS (
                SELECT 1
                FROM workflow_enable_state_revisions AS revision
                WHERE revision.tenant_id = NEW.tenant_id
                  AND revision.repository_id = NEW.repository_id
                  AND revision.workflow_id = NEW.workflow_id
                  AND revision.state_revision = 1
            )
            OR EXISTS (
                SELECT 1
                FROM workflow_enable_state_revisions AS history
                WHERE history.tenant_id = NEW.tenant_id
                  AND history.repository_id = NEW.repository_id
                  AND history.workflow_id = NEW.workflow_id
                  AND history.state_revision <> 1
            )
        THEN
            RAISE EXCEPTION 'workflow enable-state current pointer must begin at revision one'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'workflow_enable_state_current_contiguous';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id
        OR NEW.state_revision <> OLD.state_revision + 1
        OR NOT EXISTS (
            SELECT 1
            FROM workflow_enable_state_revisions AS previous
            JOIN workflow_enable_state_revisions AS successor
              ON successor.tenant_id = previous.tenant_id
             AND successor.repository_id = previous.repository_id
             AND successor.workflow_id = previous.workflow_id
             AND successor.state_revision = previous.state_revision + 1
             AND successor.workflow_path = previous.workflow_path
             AND successor.enable_state <> previous.enable_state
             AND successor.changed_at_ms >= previous.changed_at_ms
            WHERE previous.tenant_id = OLD.tenant_id
              AND previous.repository_id = OLD.repository_id
              AND previous.workflow_id = OLD.workflow_id
              AND previous.state_revision = OLD.state_revision
              AND successor.state_revision = NEW.state_revision
        )
    THEN
        RAISE EXCEPTION 'workflow enable-state current pointer transition is not exact and contiguous'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_enable_state_current_contiguous';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_workflow_enable_state_revision_current() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM workflow_enable_state_current AS current
         WHERE current.tenant_id = NEW.tenant_id
           AND current.repository_id = NEW.repository_id
           AND current.workflow_id = NEW.workflow_id
           AND current.state_revision = NEW.state_revision
    ) THEN
        RAISE EXCEPTION 'workflow enable-state revision must become current atomically'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_enable_state_revision_must_be_current';
    END IF;
    RETURN NULL;
END;
$$;

CREATE INDEX event_subject_selections_repository_time_idx
    ON event_subject_selections(tenant_id, repository_id, selected_at_ms, subject_id);

CREATE INDEX event_subject_selections_origin_idx
    ON event_subject_selections(tenant_id, origin_kind_code, origin_id);

CREATE UNIQUE INDEX event_subject_selections_manual_operation_once_idx
    ON event_subject_selections(tenant_id, origin_id)
    WHERE origin_kind_code = 3;

CREATE INDEX event_subject_progress_tenant_time_idx
    ON event_subject_progress(tenant_id, recorded_at_ms, subject_id);

ALTER TABLE event_subject_selections
    ADD CONSTRAINT event_subject_selections_repository_fk
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id)
        ON DELETE RESTRICT;

ALTER TABLE event_subject_progress
    ADD CONSTRAINT event_subject_progress_run_fk
        FOREIGN KEY (run_id)
        REFERENCES workflow_runs(id)
        ON DELETE RESTRICT;

CREATE TRIGGER event_control_subjects_immutable
    BEFORE DELETE OR UPDATE ON event_control_subjects
    FOR EACH ROW EXECUTE FUNCTION automata_event_subject_records_immutable();

CREATE TRIGGER event_control_subjects_no_truncate
    BEFORE TRUNCATE ON event_control_subjects
    FOR EACH STATEMENT EXECUTE FUNCTION automata_event_subject_records_immutable();

CREATE TRIGGER event_subject_progress_00_insert_exact
    BEFORE INSERT ON event_subject_progress
    FOR EACH ROW EXECUTE FUNCTION automata_event_subject_progress_insert_exact();

CREATE TRIGGER event_subject_progress_immutable
    BEFORE DELETE OR UPDATE ON event_subject_progress
    FOR EACH ROW EXECUTE FUNCTION automata_event_subject_records_immutable();

CREATE TRIGGER event_subject_progress_no_truncate
    BEFORE TRUNCATE ON event_subject_progress
    FOR EACH STATEMENT EXECUTE FUNCTION automata_event_subject_records_immutable();

CREATE TRIGGER event_subject_selections_immutable
    BEFORE DELETE OR UPDATE ON event_subject_selections
    FOR EACH ROW EXECUTE FUNCTION automata_event_subject_records_immutable();

CREATE TRIGGER event_subject_selections_no_truncate
    BEFORE TRUNCATE ON event_subject_selections
    FOR EACH STATEMENT EXECUTE FUNCTION automata_event_subject_records_immutable();

CREATE CONSTRAINT TRIGGER event_subject_selections_require_control
    AFTER INSERT ON event_subject_selections
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION automata_require_event_subject_control();

CREATE TRIGGER event_control_subjects_00_timeline_exact
    BEFORE INSERT ON event_control_subjects
    FOR EACH ROW EXECUTE FUNCTION automata_event_control_subject_timeline_exact();

ALTER TABLE workflow_enable_state_revisions
    ADD CONSTRAINT workflow_enable_state_revisions_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id)
        ON DELETE CASCADE;

ALTER TABLE workflow_enable_state_revisions
    ADD CONSTRAINT workflow_enable_state_revisions_workflow
        FOREIGN KEY (repository_id, workflow_id, workflow_path)
        REFERENCES workflow_definitions(repository_id, id, path)
        ON DELETE CASCADE;

CREATE TRIGGER workflow_enable_state_revisions_00_insert_guard
    BEFORE INSERT ON workflow_enable_state_revisions
    FOR EACH ROW
    EXECUTE FUNCTION automata_workflow_enable_state_revision_insert_guard();

CREATE TRIGGER workflow_enable_state_revisions_no_update_delete
    BEFORE DELETE OR UPDATE ON workflow_enable_state_revisions
    FOR EACH ROW
    EXECUTE FUNCTION automata_workflow_enable_state_revision_immutable();

CREATE TRIGGER workflow_enable_state_revisions_no_truncate
    BEFORE TRUNCATE ON workflow_enable_state_revisions
    FOR EACH STATEMENT
    EXECUTE FUNCTION automata_workflow_enable_state_revision_immutable();

CREATE CONSTRAINT TRIGGER workflow_enable_state_revisions_must_be_current
    AFTER INSERT ON workflow_enable_state_revisions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION automata_require_workflow_enable_state_revision_current();

CREATE TRIGGER workflow_enable_state_current_00_guard
    BEFORE INSERT OR DELETE OR UPDATE ON workflow_enable_state_current
    FOR EACH ROW
    EXECUTE FUNCTION automata_workflow_enable_state_current_guard();

CREATE TRIGGER workflow_enable_state_current_no_truncate
    BEFORE TRUNCATE ON workflow_enable_state_current
    FOR EACH STATEMENT
    EXECUTE FUNCTION automata_workflow_enable_state_current_guard();

ALTER TABLE github_check_subjects
    ADD COLUMN event_control_subject_id UUID;

ALTER TABLE github_check_subjects
    ADD CONSTRAINT github_check_subjects_event_control_subject_non_nil
        CHECK (
            event_control_subject_id IS NULL
            OR event_control_subject_id <> '00000000-0000-0000-0000-000000000000'::UUID
        ),
    ADD CONSTRAINT github_check_subjects_event_control_subject_unique
        UNIQUE (event_control_subject_id),
    ADD CONSTRAINT github_check_subjects_event_control_subject
        FOREIGN KEY (event_control_subject_id)
        REFERENCES event_control_subjects(control_id)
        ON DELETE RESTRICT;

CREATE FUNCTION automata_github_check_event_control_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.event_control_subject_id IS NOT NULL THEN
        RAISE EXCEPTION 'GitHub Check generalized control linkage requires an admitted run'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_event_control_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_check_event_control_update_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.event_control_subject_id IS NOT NULL
        AND NEW.event_control_subject_id IS DISTINCT FROM OLD.event_control_subject_id
    THEN
        RAISE EXCEPTION 'GitHub Check generalized control linkage is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_event_control_immutable';
    ELSIF OLD.event_control_subject_id IS NULL
        AND NEW.event_control_subject_id IS NOT NULL
    THEN
        PERFORM 1
        FROM event_control_subjects AS control
        JOIN event_subject_selections AS selection
          ON selection.tenant_id = control.tenant_id
         AND selection.subject_id = control.subject_id
         AND selection.selection_digest = control.selection_digest
        JOIN event_subject_progress AS progress
          ON progress.tenant_id = selection.tenant_id
         AND progress.subject_id = selection.subject_id
         AND progress.selection_digest = selection.selection_digest
        WHERE control.control_id = NEW.event_control_subject_id
          AND selection.tenant_id = NEW.tenant_id
          AND selection.repository_id = NEW.repository_id
          AND selection.workflow_path = NEW.subject_key
          AND (
               (progress.outcome_kind = 'admitted'
                AND progress.run_id = NEW.workflow_run_id
                AND NEW.workflow_run_id IS NOT NULL)
            OR (progress.outcome_kind IN ('skipped', 'failed')
                AND progress.run_id IS NULL
                AND NEW.workflow_run_id IS NULL)
          )
          AND (
               (NEW.origin_kind = 'provider_delivery'
                AND selection.origin_kind_name = 'provider_delivery'
                AND selection.origin_id = NEW.provider_delivery_id)
            OR (NEW.origin_kind = 'scheduled_fire'
                AND selection.origin_kind_name = 'schedule_fire'
                AND selection.origin_id = NEW.schedule_fire_id)
            OR (NEW.origin_kind = 'workflow_rerun'
                AND selection.origin_kind_name = 'workflow_run'
                AND selection.origin_id = NEW.workflow_rerun_run_id)
          );
        IF NOT FOUND THEN
            RAISE EXCEPTION 'GitHub Check generalized control linkage is inconsistent'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_event_control_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER github_check_subjects_00_event_control_insert
    BEFORE INSERT ON github_check_subjects
    FOR EACH ROW
    EXECUTE FUNCTION automata_github_check_event_control_insert_guard();

CREATE TRIGGER github_check_subjects_00_event_control_update
    BEFORE UPDATE ON github_check_subjects
    FOR EACH ROW
    EXECUTE FUNCTION automata_github_check_event_control_update_guard();
