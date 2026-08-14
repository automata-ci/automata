-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_github_provider_delivery_evidence_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub provider delivery evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_provider_delivery_evidence_immutable';
END;
$$;

CREATE FUNCTION automata_github_provider_delivery_evidence_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    inbox provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    manifest_pin RECORD;
    checks_authority github_server_service_authorities%ROWTYPE;
    private_authority github_server_service_authorities%ROWTYPE;
BEGIN

    IF NEW.authenticated_event_name = 'repository_dispatch' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM github_repository_dispatch_pending_evidence AS pending
            JOIN github_provider_manifest_revisions AS manifest
              ON manifest.tenant_id = pending.tenant_id
             AND manifest.repository_id = pending.repository_id
             AND manifest.provider_connection_id = pending.provider_connection_id
             AND manifest.manifest_revision = pending.provider_manifest_revision
             AND manifest.manifest_digest = pending.provider_manifest_digest
            WHERE pending.provider_delivery_id = NEW.provider_delivery_id
              AND pending.tenant_id = NEW.tenant_id
              AND pending.repository_id = NEW.repository_id
              AND pending.provider_connection_id = NEW.provider_connection_id
              AND manifest.provider_installation_id = NEW.provider_installation_id
              AND manifest.github_repository_id = NEW.github_repository_id
              AND manifest.github_repository_name = NEW.github_repository_name
              AND manifest.repository_visibility = NEW.repository_visibility
              AND pending.github_repository_owner_id = NEW.github_repository_owner_id
              AND pending.provider_manifest_revision = NEW.provider_manifest_revision
              AND pending.provider_manifest_digest = NEW.provider_manifest_digest
              AND pending.authenticated_webhook_verifier_fingerprint_sha256 =
                  NEW.authenticated_webhook_verifier_fingerprint_sha256
              AND pending.authenticated_webhook_verifier_revision =
                  NEW.authenticated_webhook_verifier_revision
              AND pending.authenticated_event_envelope_version =
                  NEW.authenticated_event_envelope_version
              AND pending.authenticated_event_name = NEW.authenticated_event_name
              AND pending.authenticated_event_git_ref = NEW.authenticated_event_git_ref
              AND pending.checks_authority_id = NEW.checks_authority_id
              AND pending.checks_authority_identity_digest =
                  NEW.checks_authority_identity_digest
              AND pending.checks_authority_app_configuration_revision =
                  NEW.checks_authority_app_configuration_revision
              AND pending.checks_authority_policy_revision =
                  NEW.checks_authority_policy_revision
              AND pending.private_source_authority_id IS NOT DISTINCT FROM
                  NEW.private_source_authority_id
              AND pending.private_source_authority_identity_digest IS NOT DISTINCT FROM
                  NEW.private_source_authority_identity_digest
              AND pending.private_source_authority_app_configuration_revision IS NOT DISTINCT FROM
                  NEW.private_source_authority_app_configuration_revision
              AND pending.private_source_authority_policy_revision IS NOT DISTINCT FROM
                  NEW.private_source_authority_policy_revision
        ) THEN
            RAISE EXCEPTION 'resolved repository dispatch does not match pending authority'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_repository_dispatch_resolution_exact';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO inbox
    FROM provider_delivery_inbox
    WHERE id = NEW.provider_delivery_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;

    SELECT * INTO repository
    FROM repositories
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.repository_id
    FOR SHARE;

    SELECT manifest_source.*,
           current_source.activated_at_ms AS current_activated_at_ms
      INTO manifest_pin
    FROM github_provider_manifest_revisions AS manifest_source
    JOIN github_provider_manifest_current AS current_source
      ON current_source.tenant_id = manifest_source.tenant_id
     AND current_source.repository_id = manifest_source.repository_id
     AND current_source.provider_connection_id = manifest_source.provider_connection_id
     AND current_source.manifest_revision = manifest_source.manifest_revision
     AND current_source.manifest_digest = manifest_source.manifest_digest
    WHERE manifest_source.tenant_id = NEW.tenant_id
      AND manifest_source.repository_id = NEW.repository_id
      AND manifest_source.provider_connection_id = NEW.provider_connection_id
      AND manifest_source.manifest_revision = NEW.provider_manifest_revision
      AND manifest_source.manifest_digest = NEW.provider_manifest_digest
    FOR SHARE OF manifest_source, current_source;

    SELECT * INTO checks_authority
    FROM github_server_service_authorities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.checks_authority_id
    FOR SHARE;

    IF NEW.private_source_authority_id IS NOT NULL THEN
        SELECT * INTO private_authority
        FROM github_server_service_authorities
        WHERE tenant_id = NEW.tenant_id
          AND id = NEW.private_source_authority_id
        FOR SHARE;
    END IF;

    IF inbox.id IS NULL
        OR repository.id IS NULL
        OR manifest_pin.provider_connection_id IS NULL
        OR checks_authority.id IS NULL
        OR inbox.provider <> 'github'
        OR inbox.connection_id <> NEW.provider_connection_id
        OR inbox.installation_id <> NEW.provider_installation_id
        OR inbox.provider_repository_id <> NEW.github_repository_id
        OR inbox.repository_identity <> NEW.github_repository_name
        OR inbox.repository_visibility <> NEW.repository_visibility
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner <> split_part(NEW.github_repository_name, '/', 1)
        OR repository.name <> split_part(NEW.github_repository_name, '/', 2)
        OR manifest_pin.provider_installation_id <> NEW.provider_installation_id
        OR manifest_pin.github_repository_id <> NEW.github_repository_id
        OR manifest_pin.github_repository_name <> NEW.github_repository_name
        OR manifest_pin.repository_visibility <> NEW.repository_visibility
        OR manifest_pin.webhook_verifier_fingerprint_sha256 <>
            NEW.authenticated_webhook_verifier_fingerprint_sha256
        OR manifest_pin.webhook_verifier_revision <>
            NEW.authenticated_webhook_verifier_revision
        OR inbox.accepted_at_ms < manifest_pin.current_activated_at_ms
        OR checks_authority.repository_id <> NEW.repository_id
        OR checks_authority.provider_connection_id <> NEW.provider_connection_id
        OR checks_authority.provider_installation_id <> NEW.provider_installation_id
        OR checks_authority.github_app_id <> manifest_pin.github_app_id
        OR checks_authority.github_repository_id <> NEW.github_repository_id
        OR checks_authority.github_repository_name <> NEW.github_repository_name
        OR checks_authority.service_scope <> 'checks_write'
        OR checks_authority.github_app_client_id <> manifest_pin.github_app_client_id
        OR checks_authority.github_app_jwt_issuer_kind <>
            manifest_pin.github_app_jwt_issuer_kind
        OR checks_authority.app_key_spki_sha256 <> manifest_pin.app_key_spki_sha256
        OR checks_authority.app_configuration_revision <>
            NEW.checks_authority_app_configuration_revision
        OR checks_authority.app_configuration_revision <>
            manifest_pin.app_configuration_revision
        OR checks_authority.policy_revision <> NEW.checks_authority_policy_revision
        OR checks_authority.policy_revision <> manifest_pin.policy_revision
        OR checks_authority.identity_digest <> NEW.checks_authority_identity_digest
        OR checks_authority.state <> 'active'
        OR checks_authority.created_at_ms > inbox.accepted_at_ms
        OR (
            NEW.repository_visibility = 'public'
            AND NEW.private_source_authority_id IS NOT NULL
        )
        OR (
            NEW.repository_visibility = 'private'
            AND (
                private_authority.id IS NULL
                OR private_authority.repository_id <> NEW.repository_id
                OR private_authority.provider_connection_id <> NEW.provider_connection_id
                OR private_authority.provider_installation_id <>
                    NEW.provider_installation_id
                OR private_authority.github_app_id <> manifest_pin.github_app_id
                OR private_authority.github_repository_id <> NEW.github_repository_id
                OR private_authority.github_repository_name <> NEW.github_repository_name
                OR private_authority.service_scope <>
                    'private_repository_source_read'
                OR private_authority.github_app_client_id <>
                    manifest_pin.github_app_client_id
                OR private_authority.github_app_jwt_issuer_kind <>
                    manifest_pin.github_app_jwt_issuer_kind
                OR private_authority.app_key_spki_sha256 <>
                    manifest_pin.app_key_spki_sha256
                OR private_authority.app_configuration_revision <>
                    NEW.private_source_authority_app_configuration_revision
                OR private_authority.app_configuration_revision <>
                    manifest_pin.app_configuration_revision
                OR private_authority.policy_revision <>
                    NEW.private_source_authority_policy_revision
                OR private_authority.policy_revision <> manifest_pin.policy_revision
                OR private_authority.identity_digest <>
                    NEW.private_source_authority_identity_digest
                OR private_authority.state <> 'active'
                OR private_authority.created_at_ms > inbox.accepted_at_ms
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub delivery evidence is not the exact current manifest and service authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_provider_delivery_evidence_authority_exact';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_provider_git_ref_canonical(value text) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $$
WITH candidate AS (
    SELECT substr(value, 12) AS branch
)
SELECT octet_length(value) BETWEEN 12 AND 1024
   AND left(value, 11) = 'refs/heads/'
   AND branch <> ''
   AND branch <> '@'
   AND left(branch, 1) NOT IN ('-', '/', '.')
   AND right(branch, 1) NOT IN ('/', '.')
   AND strpos(branch, '//') = 0
   AND strpos(branch, '..') = 0
   AND strpos(branch, '@{') = 0
   AND branch !~ '[[:cntrl:][:space:]]'
   AND strpos(branch, '~') = 0
   AND strpos(branch, '^') = 0
   AND strpos(branch, ':') = 0
   AND strpos(branch, '?') = 0
   AND strpos(branch, '*') = 0
   AND strpos(branch, '[') = 0
   AND strpos(branch, chr(92)) = 0
   AND NOT EXISTS (
       SELECT 1
       FROM unnest(string_to_array(branch, '/')) AS component(value)
       WHERE component.value = ''
          OR left(component.value, 1) = '.'
          OR right(component.value, 5) = '.lock'
   )
FROM candidate
$$;

CREATE FUNCTION automata_github_provider_manifest_canonical_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.repository_id IS DISTINCT FROM
        automata_github_provider_repository_id(
            NEW.tenant_id,
            NEW.github_repository_id
        )
    THEN
        RAISE EXCEPTION 'GitHub provider manifest repository UUID is non-canonical'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_revisions_repository_id_canonical';
    ELSIF NEW.manifest_digest IS DISTINCT FROM
        automata_github_provider_manifest_digest(NEW)
    THEN
        RAISE EXCEPTION 'GitHub provider manifest digest is non-canonical'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_revisions_digest_canonical';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_provider_manifest_current_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    prior github_provider_manifest_revisions%ROWTYPE;
    replacement github_provider_manifest_revisions%ROWTYPE;
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
        OR replacement.provider_installation_id IS DISTINCT FROM prior.provider_installation_id
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

    app_evidence_changed = replacement.app_key_spki_sha256
        IS DISTINCT FROM prior.app_key_spki_sha256;
    verifier_evidence_changed = replacement.webhook_verifier_fingerprint_sha256
        IS DISTINCT FROM prior.webhook_verifier_fingerprint_sha256;
    runtime_policy_changed = replacement.runtime_policy_digest
        IS DISTINCT FROM prior.runtime_policy_digest;
    policy_evidence_changed =
        replacement.repository_visibility IS DISTINCT FROM prior.repository_visibility
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

    IF NOT (app_evidence_changed OR verifier_evidence_changed OR policy_evidence_changed)
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

CREATE FUNCTION automata_github_provider_manifest_current_no_truncate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub provider manifest current pointers cannot be truncated'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_provider_manifest_current_removal_forbidden';
END;
$$;

CREATE FUNCTION automata_github_provider_repository_id(text, bigint) RETURNS uuid
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
WITH raw(bytes) AS (
    SELECT substring(
        pg_catalog.sha256(
            pg_catalog.convert_to('automata.admission.repository.v1', 'UTF8')
            || pg_catalog.decode('00', 'hex')
            || automata_digest_part(
                pg_catalog.convert_to($1, 'UTF8')
            )
            || automata_digest_part(
                pg_catalog.convert_to('github', 'UTF8')
            )
            || automata_digest_part(
                pg_catalog.convert_to($2::TEXT, 'UTF8')
            )
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

CREATE TABLE github_provider_manifest_revisions (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid CONSTRAINT github_provider_manifest_revisi_provider_connection_id_not_null NOT NULL,
    manifest_revision bigint NOT NULL,
    manifest_digest bytea NOT NULL,
    provider_installation_id bigint CONSTRAINT github_provider_manifest_revi_provider_installation_id_not_null NOT NULL,
    github_repository_id bigint CONSTRAINT github_provider_manifest_revision_github_repository_id_not_null NOT NULL,
    github_repository_name text CONSTRAINT github_provider_manifest_revisi_github_repository_name_not_null NOT NULL COLLATE pg_catalog."C",
    repository_visibility text CONSTRAINT github_provider_manifest_revisio_repository_visibility_not_null NOT NULL COLLATE pg_catalog."C",
    github_app_id bigint NOT NULL,
    github_app_client_id text CONSTRAINT github_provider_manifest_revision_github_app_client_id_not_null NOT NULL COLLATE pg_catalog."C",
    github_app_jwt_issuer_kind text CONSTRAINT github_provider_manifest_re_github_app_jwt_issuer_kind_not_null NOT NULL COLLATE pg_catalog."C",
    app_key_spki_sha256 bytea NOT NULL,
    app_configuration_revision bigint CONSTRAINT github_provider_manifest_re_app_configuration_revision_not_null NOT NULL,
    webhook_verifier_fingerprint_sha256 bytea CONSTRAINT github_provider_manifest_re_webhook_verifier_fingerpri_not_null NOT NULL,
    webhook_verifier_revision bigint CONSTRAINT github_provider_manifest_rev_webhook_verifier_revision_not_null NOT NULL,
    policy_revision bigint NOT NULL,
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    event_name text NOT NULL COLLATE pg_catalog."C",
    git_ref text NOT NULL COLLATE pg_catalog."C",
    check_subject_key text NOT NULL COLLATE pg_catalog."C",
    check_name text NOT NULL COLLATE pg_catalog."C",
    github_web_origin text NOT NULL COLLATE pg_catalog."C",
    github_api_origin text NOT NULL COLLATE pg_catalog."C",
    github_archive_origin text CONSTRAINT github_provider_manifest_revisio_github_archive_origin_not_null NOT NULL COLLATE pg_catalog."C",
    github_rest_api_version text CONSTRAINT github_provider_manifest_revis_github_rest_api_version_not_null NOT NULL COLLATE pg_catalog."C",
    github_rest_accept text NOT NULL COLLATE pg_catalog."C",
    github_archive_accept text CONSTRAINT github_provider_manifest_revisio_github_archive_accept_not_null NOT NULL COLLATE pg_catalog."C",
    repository_source_authentication text CONSTRAINT github_provider_manifest_re_repository_source_authenti_not_null NOT NULL COLLATE pg_catalog."C",
    repository_source_revision text CONSTRAINT github_provider_manifest_re_repository_source_revision_not_null NOT NULL COLLATE pg_catalog."C",
    repository_archive_format text CONSTRAINT github_provider_manifest_rev_repository_archive_format_not_null NOT NULL COLLATE pg_catalog."C",
    webhook_max_body_bytes bigint CONSTRAINT github_provider_manifest_revisi_webhook_max_body_bytes_not_null NOT NULL,
    webhook_accept_timeout_ms bigint CONSTRAINT github_provider_manifest_rev_webhook_accept_timeout_ms_not_null NOT NULL,
    push_webhook_max_commits bigint CONSTRAINT github_provider_manifest_revi_push_webhook_max_commits_not_null NOT NULL,
    path_filter_max_commits bigint CONSTRAINT github_provider_manifest_revis_path_filter_max_commits_not_null NOT NULL,
    path_filter_max_changed_files bigint CONSTRAINT github_provider_manifest_re_path_filter_max_changed_fi_not_null NOT NULL,
    archive_max_compressed_bytes bigint CONSTRAINT github_provider_manifest_re_archive_max_compressed_byt_not_null NOT NULL,
    archive_max_decompressed_bytes bigint CONSTRAINT github_provider_manifest_re_archive_max_decompressed_b_not_null NOT NULL,
    archive_max_entries bigint NOT NULL,
    archive_max_expanded_bytes bigint CONSTRAINT github_provider_manifest_re_archive_max_expanded_bytes_not_null NOT NULL,
    archive_max_entry_path_bytes bigint CONSTRAINT github_provider_manifest_re_archive_max_entry_path_byt_not_null NOT NULL,
    archive_max_workflows bigint CONSTRAINT github_provider_manifest_revisio_archive_max_workflows_not_null NOT NULL,
    workflow_max_bytes bigint NOT NULL,
    registered_at_ms bigint NOT NULL,
    authority_profile text NOT NULL COLLATE pg_catalog."C",
    runner_policy_digest bytea CONSTRAINT github_provider_manifest_revision_runner_policy_digest_not_null NOT NULL,
    runner_policy_object_key text CONSTRAINT github_provider_manifest_revi_runner_policy_object_key_not_null NOT NULL COLLATE pg_catalog."C",
    runner_policy_size_bytes bigint CONSTRAINT github_provider_manifest_revi_runner_policy_size_bytes_not_null NOT NULL,
    runner_policy_media_type text CONSTRAINT github_provider_manifest_revi_runner_policy_media_type_not_null NOT NULL COLLATE pg_catalog."C",
    runtime_policy_revision bigint CONSTRAINT github_provider_manifest_revis_runtime_policy_revision_not_null NOT NULL,
    runtime_policy_digest bytea CONSTRAINT github_provider_manifest_revisio_runtime_policy_digest_not_null NOT NULL,
    workflow_selection_kind text CONSTRAINT github_provider_manifest_revis_workflow_selection_kind_not_null NOT NULL COLLATE pg_catalog."C",
    github_repository_owner_id bigint,
    CONSTRAINT github_provider_manifest_revisions_app_client_shape CHECK ((((octet_length(github_app_client_id) >= 1) AND (octet_length(github_app_client_id) <= 128)) AND (github_app_client_id ~ '^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$'::text))),
    CONSTRAINT github_provider_manifest_revisions_archive_limits CHECK (((archive_max_compressed_bytes = 268435456) AND (archive_max_decompressed_bytes = '2147483648'::bigint) AND (archive_max_entries = 100000) AND (archive_max_expanded_bytes = 1073741824) AND (archive_max_entry_path_bytes = 4096) AND (archive_max_workflows = 256) AND (workflow_max_bytes = 1048576))),
    CONSTRAINT github_provider_manifest_revisions_authority_profile CHECK ((authority_profile = ANY (ARRAY['standard'::text, 'credential_free'::text]))),
    CONSTRAINT github_provider_manifest_revisions_check_name_shape CHECK ((((octet_length(check_name) >= 1) AND (octet_length(check_name) <= 255)) AND (btrim(check_name) = check_name) AND (check_name !~ '[^ -~]'::text))),
    CONSTRAINT github_provider_manifest_revisions_digest_shape CHECK (((octet_length(manifest_digest) = 32) AND (octet_length(app_key_spki_sha256) = 32) AND (octet_length(webhook_verifier_fingerprint_sha256) = 32) AND (webhook_verifier_fingerprint_sha256 <> decode(repeat('00'::text, 32), 'hex'::text)))),
    CONSTRAINT github_provider_manifest_revisions_jwt_issuer CHECK ((github_app_jwt_issuer_kind = ANY (ARRAY['app_client_id'::text, 'app_id'::text]))),
    CONSTRAINT github_provider_manifest_revisions_non_nil CHECK (((repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT github_provider_manifest_revisions_origins_exact CHECK (((github_web_origin = 'https://github.com/'::text) AND (github_api_origin = 'https://api.github.com/'::text) AND (github_archive_origin = 'https://codeload.github.com/'::text))),
    CONSTRAINT github_provider_manifest_revisions_owner_id_shape CHECK (((github_repository_owner_id IS NULL) OR (github_repository_owner_id > 0))),
    CONSTRAINT github_provider_manifest_revisions_positive CHECK (((manifest_revision > 0) AND (provider_installation_id > 0) AND (github_repository_id > 0) AND (github_app_id > 0) AND (app_configuration_revision > 0) AND (webhook_verifier_revision > 0) AND (policy_revision > 0))),
    CONSTRAINT github_provider_manifest_revisions_provider_semantics_exact CHECK (((github_rest_api_version = '2026-03-10'::text) AND (github_rest_accept = 'application/vnd.github+json'::text) AND (github_archive_accept = 'application/octet-stream'::text) AND (((repository_visibility = 'public'::text) AND (repository_source_authentication = 'anonymous_public'::text)) OR ((repository_visibility = 'private'::text) AND (repository_source_authentication = 'github_app_installation_token'::text))) AND (repository_source_revision = 'exact_sha'::text) AND (repository_archive_format = 'tar_gzip'::text))),
    CONSTRAINT github_provider_manifest_revisions_repository_id_canonical CHECK ((repository_id = automata_github_provider_repository_id(tenant_id, github_repository_id))),
    CONSTRAINT github_provider_manifest_revisions_repository_name CHECK (((array_length(string_to_array(github_repository_name, '/'::text), 1) = 2) AND ((octet_length(split_part(github_repository_name, '/'::text, 1)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 1)) <= 39)) AND (split_part(github_repository_name, '/'::text, 1) ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$'::text) AND (split_part(github_repository_name, '/'::text, 1) !~ '--'::text) AND ((octet_length(split_part(github_repository_name, '/'::text, 2)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 2)) <= 100)) AND (split_part(github_repository_name, '/'::text, 2) ~ '^[A-Za-z0-9._-]+$'::text) AND (split_part(github_repository_name, '/'::text, 2) <> ALL (ARRAY['.'::text, '..'::text])) AND (split_part(github_repository_name, '/'::text, 2) !~* '[.]git$'::text))),
    CONSTRAINT github_provider_manifest_revisions_runner_policy_shape CHECK (((octet_length(runner_policy_digest) = 32) AND ((octet_length(runner_policy_object_key) >= 1) AND (octet_length(runner_policy_object_key) <= 1024)) AND (btrim(runner_policy_object_key) = runner_policy_object_key) AND (runner_policy_object_key !~ '[[:cntrl:]]'::text) AND (runner_policy_object_key = (('github/runner-policy/v1/'::text || encode(runner_policy_digest, 'hex'::text)) || '.json'::text)) AND ((runner_policy_size_bytes >= 1) AND (runner_policy_size_bytes <= 65536)) AND (runner_policy_media_type = 'application/vnd.automata.github-runner-policy+json'::text))),
    CONSTRAINT github_provider_manifest_revisions_runtime_policy_shape CHECK (((runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32))),
    CONSTRAINT github_provider_manifest_revisions_selector_exact CHECK (((event_name = 'push'::text) AND automata_github_provider_git_ref_canonical(git_ref) AND (workflow_selection_kind = 'all_direct'::text) AND (check_subject_key = '.ci/workflows'::text) AND (workflow_path = '.ci/workflows'::text))),
    CONSTRAINT github_provider_manifest_revisions_time CHECK ((registered_at_ms >= 0)),
    CONSTRAINT github_provider_manifest_revisions_visibility_exact CHECK ((repository_visibility = ANY (ARRAY['public'::text, 'private'::text]))),
    CONSTRAINT github_provider_manifest_revisions_webhook_limits CHECK (((webhook_max_body_bytes = 26214400) AND (webhook_accept_timeout_ms = 7000) AND (push_webhook_max_commits = 2048) AND (path_filter_max_commits = 1000) AND (path_filter_max_changed_files = 3000)))
);

CREATE FUNCTION automata_github_provider_manifest_digest(github_provider_manifest_revisions) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.github-provider-manifest', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || automata_digest_part(pg_catalog.convert_to(($1).tenant_id, 'UTF8'))
    || automata_digest_part(pg_catalog.uuid_send(($1).repository_id))
    || automata_digest_part(pg_catalog.uuid_send(($1).provider_connection_id))
    || automata_digest_part(pg_catalog.int8send(($1).provider_installation_id))
    || automata_digest_part(pg_catalog.int8send(($1).github_repository_id))
    || CASE WHEN ($1).github_repository_owner_id IS NULL
        THEN ''::BYTEA
        ELSE automata_digest_part(
            pg_catalog.int8send(($1).github_repository_owner_id)
        )
       END
    || automata_digest_part(pg_catalog.convert_to(($1).github_repository_name, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).repository_visibility, 'UTF8'))
    || automata_digest_part(pg_catalog.int8send(($1).github_app_id))
    || automata_digest_part(pg_catalog.convert_to(($1).github_app_client_id, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).github_app_jwt_issuer_kind, 'UTF8'))
    || automata_digest_part(($1).app_key_spki_sha256)
    || automata_digest_part(pg_catalog.int8send(($1).app_configuration_revision))
    || automata_digest_part(($1).webhook_verifier_fingerprint_sha256)
    || automata_digest_part(pg_catalog.int8send(($1).webhook_verifier_revision))
    || automata_digest_part(pg_catalog.int8send(($1).policy_revision))
    || automata_digest_part(pg_catalog.convert_to(($1).authority_profile, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).runner_policy_object_key, 'UTF8'))
    || automata_digest_part(($1).runner_policy_digest)
    || automata_digest_part(pg_catalog.int8send(($1).runner_policy_size_bytes))
    || automata_digest_part(pg_catalog.convert_to(($1).runner_policy_media_type, 'UTF8'))
    || automata_digest_part(pg_catalog.int8send(($1).runtime_policy_revision))
    || automata_digest_part(($1).runtime_policy_digest)
    || automata_digest_part(pg_catalog.int8send(($1).manifest_revision))
    || automata_digest_part(pg_catalog.convert_to(($1).workflow_path, 'UTF8'))
    || automata_digest_part(
        pg_catalog.convert_to(($1).workflow_selection_kind, 'UTF8')
    )
    || automata_digest_part(pg_catalog.convert_to(($1).event_name, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).git_ref, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).check_subject_key, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).check_name, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).github_web_origin, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).github_api_origin, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).github_archive_origin, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).github_rest_api_version, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).github_rest_accept, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).github_archive_accept, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).repository_source_authentication, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).repository_source_revision, 'UTF8'))
    || automata_digest_part(pg_catalog.convert_to(($1).repository_archive_format, 'UTF8'))
    || automata_digest_part(pg_catalog.int8send(($1).webhook_max_body_bytes))
    || automata_digest_part(pg_catalog.int8send(($1).webhook_accept_timeout_ms))
    || automata_digest_part(pg_catalog.int8send(($1).push_webhook_max_commits))
    || automata_digest_part(pg_catalog.int8send(($1).path_filter_max_commits))
    || automata_digest_part(pg_catalog.int8send(($1).path_filter_max_changed_files))
    || automata_digest_part(pg_catalog.int8send(($1).archive_max_compressed_bytes))
    || automata_digest_part(pg_catalog.int8send(($1).archive_max_decompressed_bytes))
    || automata_digest_part(pg_catalog.int8send(($1).archive_max_entries))
    || automata_digest_part(pg_catalog.int8send(($1).archive_max_expanded_bytes))
    || automata_digest_part(pg_catalog.int8send(($1).archive_max_entry_path_bytes))
    || automata_digest_part(pg_catalog.int8send(($1).archive_max_workflows))
    || automata_digest_part(pg_catalog.int8send(($1).workflow_max_bytes))
)
$_$;

CREATE FUNCTION automata_digest_part(bytea) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
SELECT pg_catalog.int8send(pg_catalog.octet_length($1)::BIGINT) || $1
$_$;

CREATE FUNCTION automata_github_provider_manifest_repository_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    repository repositories%ROWTYPE;
BEGIN
    SELECT * INTO repository
    FROM repositories
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.repository_id
    FOR SHARE;

    IF NOT FOUND
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner || '/' || repository.name <> NEW.github_repository_name
    THEN
        RAISE EXCEPTION 'GitHub provider manifest repository identity is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_repository_exact';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_provider_manifest_repository_identity_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM github_provider_manifest_revisions AS manifest
        WHERE manifest.tenant_id = OLD.tenant_id
          AND manifest.repository_id = OLD.id
          AND (
              NEW.tenant_id IS DISTINCT FROM manifest.tenant_id
              OR NEW.id IS DISTINCT FROM manifest.repository_id
              OR NEW.scm_provider IS DISTINCT FROM 'github'
              OR NEW.provider_repository_id IS DISTINCT FROM manifest.github_repository_id::TEXT
              OR NEW.owner || '/' || NEW.name
                    IS DISTINCT FROM manifest.github_repository_name
          )
    ) THEN
        RAISE EXCEPTION 'manifest-bound GitHub repository identity is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_repository_identity_immutable';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_provider_manifest_revision_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub provider manifest revisions are immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_provider_manifest_revisions_immutable';
END;
$$;

CREATE FUNCTION automata_github_repository_dispatch_pending_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'pending repository-dispatch evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_repository_dispatch_pending_immutable';
END;
$$;

CREATE FUNCTION automata_github_repository_dispatch_pending_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM provider_delivery_inbox AS inbox
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = NEW.tenant_id
         AND manifest.repository_id = NEW.repository_id
         AND manifest.provider_connection_id = NEW.provider_connection_id
         AND manifest.manifest_revision = NEW.provider_manifest_revision
         AND manifest.manifest_digest = NEW.provider_manifest_digest
        JOIN github_provider_manifest_current AS current_manifest
          ON current_manifest.tenant_id = manifest.tenant_id
         AND current_manifest.repository_id = manifest.repository_id
         AND current_manifest.provider_connection_id = manifest.provider_connection_id
         AND current_manifest.manifest_revision = manifest.manifest_revision
         AND current_manifest.manifest_digest = manifest.manifest_digest
        JOIN repositories AS repository
          ON repository.tenant_id = manifest.tenant_id
         AND repository.id = manifest.repository_id
        JOIN github_server_service_authorities AS checks
          ON checks.tenant_id = NEW.tenant_id
         AND checks.id = NEW.checks_authority_id
        LEFT JOIN github_server_service_authorities AS private_source
          ON private_source.tenant_id = NEW.tenant_id
         AND private_source.id = NEW.private_source_authority_id
        WHERE inbox.id = NEW.provider_delivery_id
          AND inbox.tenant_id = NEW.tenant_id
          AND inbox.provider = 'github'
          AND inbox.raw_event_media_type =
              'application/vnd.automata.github-authenticated-event+json'
          AND inbox.connection_id = manifest.provider_connection_id
          AND inbox.installation_id = manifest.provider_installation_id
          AND inbox.provider_repository_id = manifest.github_repository_id
          AND inbox.repository_identity = manifest.github_repository_name
          AND inbox.repository_visibility = manifest.repository_visibility
          AND inbox.accepted_at_ms >= current_manifest.activated_at_ms
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id = manifest.github_repository_id::TEXT
          AND repository.owner = split_part(manifest.github_repository_name, '/', 1)
          AND repository.name = split_part(manifest.github_repository_name, '/', 2)
          AND manifest.webhook_verifier_fingerprint_sha256 =
              NEW.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              NEW.authenticated_webhook_verifier_revision
          AND checks.repository_id = NEW.repository_id
          AND checks.provider_connection_id = manifest.provider_connection_id
          AND checks.provider_installation_id = manifest.provider_installation_id
          AND checks.github_app_id = manifest.github_app_id
          AND checks.github_repository_id = manifest.github_repository_id
          AND checks.github_repository_name = manifest.github_repository_name
          AND checks.service_scope = 'checks_write'
          AND checks.identity_digest = NEW.checks_authority_identity_digest
          AND checks.app_configuration_revision =
              NEW.checks_authority_app_configuration_revision
          AND checks.app_configuration_revision = manifest.app_configuration_revision
          AND checks.policy_revision = NEW.checks_authority_policy_revision
          AND checks.policy_revision = manifest.policy_revision
          AND checks.state = 'active'
          AND checks.created_at_ms <= inbox.accepted_at_ms
          AND (
              manifest.repository_visibility = 'public'
              AND NEW.private_source_authority_id IS NULL
              OR manifest.repository_visibility = 'private'
              AND private_source.id = NEW.private_source_authority_id
              AND private_source.repository_id = NEW.repository_id
              AND private_source.provider_connection_id = manifest.provider_connection_id
              AND private_source.provider_installation_id = manifest.provider_installation_id
              AND private_source.github_app_id = manifest.github_app_id
              AND private_source.github_repository_id = manifest.github_repository_id
              AND private_source.github_repository_name = manifest.github_repository_name
              AND private_source.service_scope = 'private_repository_source_read'
              AND private_source.identity_digest =
                  NEW.private_source_authority_identity_digest
              AND private_source.app_configuration_revision =
                  NEW.private_source_authority_app_configuration_revision
              AND private_source.app_configuration_revision =
                  manifest.app_configuration_revision
              AND private_source.policy_revision =
                  NEW.private_source_authority_policy_revision
              AND private_source.policy_revision = manifest.policy_revision
              AND private_source.state = 'active'
              AND private_source.created_at_ms <= inbox.accepted_at_ms
          )
    ) THEN
        RAISE EXCEPTION 'repository dispatch does not match current provider authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_repository_dispatch_pending_authority_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_runtime_authority_envelope_digest(envelope_schema integer, wrapping_key_id text, wrapped_data_key bytea, nonce bytea, ciphertext bytea) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
    SELECT pg_catalog.sha256(
        pg_catalog.convert_to(
            'automata.store.github-runtime-authority-envelope.v1', 'UTF8'
        ) || pg_catalog.decode('00', 'hex')
        || pg_catalog.int2send(envelope_schema::SMALLINT)
        || automata_github_runtime_authority_hash_bytes(
            pg_catalog.convert_to(wrapping_key_id, 'UTF8')
        )
        || automata_github_runtime_authority_hash_bytes(wrapped_data_key)
        || automata_github_runtime_authority_hash_bytes(nonce)
        || automata_github_runtime_authority_hash_bytes(ciphertext)
    )
$$;

CREATE TABLE github_runtime_authority_issuances (
    tenant_id text NOT NULL,
    attempt_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    lease_id uuid NOT NULL,
    lease_issued_at_ms bigint NOT NULL,
    lease_expires_at_ms bigint NOT NULL,
    run_id uuid NOT NULL,
    job_id uuid NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_id uuid NOT NULL,
    runner_session_epoch bigint CONSTRAINT github_runtime_authority_issuance_runner_session_epoch_not_null NOT NULL,
    runner_generation bigint NOT NULL,
    runner_slot integer NOT NULL,
    job_ir_schema integer NOT NULL,
    job_ir_size_bytes bigint NOT NULL,
    job_ir_digest bytea NOT NULL,
    repository_id uuid NOT NULL,
    github_repository_id bigint CONSTRAINT github_runtime_authority_issuance_github_repository_id_not_null NOT NULL,
    github_repository_name text CONSTRAINT github_runtime_authority_issuan_github_repository_name_not_null NOT NULL COLLATE pg_catalog."C",
    authority_namespace text NOT NULL COLLATE pg_catalog."C",
    policy_digest bytea NOT NULL,
    issuer_fingerprint bytea NOT NULL,
    configuration_fingerprint bytea CONSTRAINT github_runtime_authority_iss_configuration_fingerprint_not_null NOT NULL,
    requested_at_ms bigint NOT NULL,
    request_deadline_at_ms bigint CONSTRAINT github_runtime_authority_issuan_request_deadline_at_ms_not_null NOT NULL,
    conservative_expiry_at_ms bigint CONSTRAINT github_runtime_authority_iss_conservative_expiry_at_ms_not_null NOT NULL,
    state text DEFAULT 'claimed'::text NOT NULL,
    mint_attempt_count smallint DEFAULT 1 NOT NULL,
    mint_claim_fence bigint DEFAULT 1 NOT NULL,
    mint_claim_owner_id uuid NOT NULL,
    mint_claimed_at_ms bigint NOT NULL,
    mint_claim_expires_at_ms bigint,
    mint_started_at_ms bigint,
    indeterminate_at_ms bigint,
    provider_expires_at_ms bigint,
    safe_erase_after_ms bigint,
    plaintext_schema integer,
    plaintext_size_bytes bigint,
    plaintext_digest bytea,
    aad_digest bytea,
    envelope_schema integer,
    wrapping_key_id text COLLATE pg_catalog."C",
    wrapped_data_key bytea,
    nonce bytea,
    ciphertext bytea,
    ready_at_ms bigint,
    revoke_pending_at_ms bigint,
    revoke_attempt_count smallint DEFAULT 0 CONSTRAINT github_runtime_authority_issuance_revoke_attempt_count_not_null NOT NULL,
    revoke_claim_fence bigint DEFAULT 0 NOT NULL,
    revoke_claim_owner_id uuid,
    revoke_claimed_at_ms bigint,
    revoke_claim_expires_at_ms bigint,
    next_revoke_at_ms bigint,
    last_revoke_failure_kind text COLLATE pg_catalog."C",
    revoked_at_ms bigint,
    terminal_reason text,
    state_updated_at_ms bigint NOT NULL,
    provider_connection_id uuid CONSTRAINT github_runtime_authority_issuan_provider_connection_id_not_null NOT NULL,
    provider_installation_id bigint CONSTRAINT github_runtime_authority_issu_provider_installation_id_not_null NOT NULL,
    commit_disposition text COLLATE pg_catalog."C",
    next_mint_at_ms bigint,
    last_mint_rejection_kind text COLLATE pg_catalog."C",
    rejected_at_ms bigint,
    quarantine_at_ms bigint,
    quarantine_kind text COLLATE pg_catalog."C",
    github_app_id bigint NOT NULL,
    github_app_client_id text CONSTRAINT github_runtime_authority_issuance_github_app_client_id_not_null NOT NULL COLLATE pg_catalog."C",
    github_app_jwt_issuer_kind text CONSTRAINT github_runtime_authority_is_github_app_jwt_issuer_kind_not_null NOT NULL COLLATE pg_catalog."C",
    github_app_jwt_issuer_value text CONSTRAINT github_runtime_authority_is_github_app_jwt_issuer_valu_not_null NOT NULL COLLATE pg_catalog."C",
    preparation_selection_id uuid CONSTRAINT github_runtime_authority_issu_preparation_selection_id_not_null NOT NULL,
    preparation_selection_owner_id uuid CONSTRAINT github_runtime_authority_is_preparation_selection_owne_not_null NOT NULL,
    preparation_selection_generation bigint CONSTRAINT github_runtime_authority_is_preparation_selection_gene_not_null NOT NULL,
    preparation_selection_descriptor_digest bytea CONSTRAINT github_runtime_authority_is_preparation_selection_desc_not_null NOT NULL,
    preparation_selection_claimed_at_ms bigint CONSTRAINT github_runtime_authority_is_preparation_selection_clai_not_null NOT NULL,
    preparation_selection_expires_at_ms bigint CONSTRAINT github_runtime_authority_is_preparation_selection_expi_not_null NOT NULL,
    activation_selection_id uuid CONSTRAINT github_runtime_authority_issua_activation_selection_id_not_null NOT NULL,
    activation_selection_owner_id uuid CONSTRAINT github_runtime_authority_is_activation_selection_owner_not_null NOT NULL,
    activation_selection_generation bigint CONSTRAINT github_runtime_authority_is_activation_selection_gener_not_null NOT NULL,
    activation_selection_input_digest bytea CONSTRAINT github_runtime_authority_is_activation_selection_input_not_null NOT NULL,
    activation_selection_claimed_at_ms bigint CONSTRAINT github_runtime_authority_is_activation_selection_claim_not_null NOT NULL,
    activation_selection_expires_at_ms bigint CONSTRAINT github_runtime_authority_is_activation_selection_expir_not_null NOT NULL,
    materialization_selection_id uuid CONSTRAINT github_runtime_authority_is_materialization_selection__not_null NOT NULL,
    materialization_selection_owner_id uuid CONSTRAINT github_runtime_authority_i_materialization_selection__not_null1 NOT NULL,
    materialization_selection_generation bigint CONSTRAINT github_runtime_authority_i_materialization_selection__not_null2 NOT NULL,
    materialization_selection_descriptor_digest bytea CONSTRAINT github_runtime_authority_i_materialization_selection__not_null3 NOT NULL,
    materialization_selection_claimed_at_ms bigint CONSTRAINT github_runtime_authority_i_materialization_selection__not_null4 NOT NULL,
    materialization_selection_expires_at_ms bigint CONSTRAINT github_runtime_authority_i_materialization_selection__not_null5 NOT NULL,
    mint_provider_request_millis bigint,
    operation_request_kind text COLLATE pg_catalog."C",
    operation_request_claim_fence bigint,
    operation_request_claim_owner_id uuid,
    operation_request_observed_at_ms bigint,
    operation_request_retry_at_ms bigint,
    operation_request_failure_kind text COLLATE pg_catalog."C",
    operation_request_commit_disposition text COLLATE pg_catalog."C",
    operation_request_provider_expires_at_ms bigint,
    operation_request_safe_erase_after_ms bigint,
    operation_request_plaintext_schema integer,
    operation_request_plaintext_size_bytes bigint,
    operation_request_plaintext_digest bytea,
    operation_request_aad_digest bytea,
    operation_request_envelope_digest bytea,
    CONSTRAINT github_runtime_authority_app_identity_shape CHECK (((github_app_id > 0) AND ((octet_length(github_app_client_id) >= 1) AND (octet_length(github_app_client_id) <= 128)) AND (github_app_client_id ~ '^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$'::text) AND (github_app_jwt_issuer_kind = ANY (ARRAY['app_client_id'::text, 'app_id'::text])) AND ((octet_length(github_app_jwt_issuer_value) >= 1) AND (octet_length(github_app_jwt_issuer_value) <= 128)) AND (github_app_jwt_issuer_value ~ '^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$'::text) AND (github_app_jwt_issuer_value =
CASE github_app_jwt_issuer_kind
    WHEN 'app_client_id'::text THEN github_app_client_id
    WHEN 'app_id'::text THEN (github_app_id)::text
    ELSE NULL::text
END))),
    CONSTRAINT github_runtime_authority_current_job_ir_current CHECK (((job_ir_schema = 1) AND ((job_ir_size_bytes >= 1) AND (job_ir_size_bytes <= 16777216)) AND (octet_length(job_ir_digest) = 32))),
    CONSTRAINT github_runtime_authority_envelope_complete CHECK ((((envelope_schema IS NULL) = (wrapping_key_id IS NULL)) AND ((envelope_schema IS NULL) = (wrapped_data_key IS NULL)) AND ((envelope_schema IS NULL) = (nonce IS NULL)) AND ((envelope_schema IS NULL) = (ciphertext IS NULL)))),
    CONSTRAINT github_runtime_authority_envelope_shape CHECK (((envelope_schema IS NULL) OR ((safe_erase_after_ms IS NOT NULL) AND (envelope_schema = 1) AND ((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 64)) AND (wrapping_key_id ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'::text) AND ((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 65536)) AND (octet_length(nonce) = 12) AND ((octet_length(ciphertext))::numeric = ((plaintext_size_bytes)::numeric + (16)::numeric)) AND (octet_length(ciphertext) <= 65552)))),
    CONSTRAINT github_runtime_authority_execution_numbers CHECK (((fencing_token > 0) AND (runner_session_epoch > 0) AND (runner_generation > 0) AND ((runner_slot >= 1) AND (runner_slot <= 65535)))),
    CONSTRAINT github_runtime_authority_github_repository_id_positive CHECK ((github_repository_id > 0)),
    CONSTRAINT github_runtime_authority_github_repository_name_shape CHECK ((((octet_length(github_repository_name) >= 3) AND (octet_length(github_repository_name) <= 140)) AND (github_repository_name ~ '^[^/]+/[^/]+$'::text) AND ((octet_length(split_part(github_repository_name, '/'::text, 1)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 1)) <= 39)) AND (split_part(github_repository_name, '/'::text, 1) ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'::text) AND (split_part(github_repository_name, '/'::text, 1) !~~ '%--%'::text) AND ((octet_length(split_part(github_repository_name, '/'::text, 2)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 2)) <= 100)) AND (split_part(github_repository_name, '/'::text, 2) ~ '^[A-Za-z0-9._-]+$'::text) AND (split_part(github_repository_name, '/'::text, 2) <> ALL (ARRAY['.'::text, '..'::text])) AND (lower(split_part(github_repository_name, '/'::text, 2)) !~~ '%.git'::text))),
    CONSTRAINT github_runtime_authority_identity_digests CHECK (((octet_length(policy_digest) = 32) AND (octet_length(issuer_fingerprint) = 32) AND (octet_length(configuration_fingerprint) = 32))),
    CONSTRAINT github_runtime_authority_mint_claim_bounds CHECK ((((mint_attempt_count >= 1) AND (mint_attempt_count <= 32)) AND (mint_claim_fence > 0) AND (mint_claimed_at_ms >= requested_at_ms) AND ((mint_claim_expires_at_ms IS NULL) OR ((mint_claim_expires_at_ms > mint_claimed_at_ms) AND (mint_claim_expires_at_ms <= request_deadline_at_ms) AND ((mint_claim_expires_at_ms - mint_claimed_at_ms) <= 120000))) AND ((next_mint_at_ms IS NULL) OR ((next_mint_at_ms > state_updated_at_ms) AND (next_mint_at_ms < request_deadline_at_ms) AND ((next_mint_at_ms - state_updated_at_ms) <= 120000))))),
    CONSTRAINT github_runtime_authority_mint_failure_shape CHECK (((last_mint_rejection_kind IS NULL) OR (((octet_length(last_mint_rejection_kind) >= 1) AND (octet_length(last_mint_rejection_kind) <= 128)) AND (last_mint_rejection_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)))),
    CONSTRAINT github_runtime_authority_mint_provider_request_shape CHECK ((((mint_started_at_ms IS NULL) AND (mint_provider_request_millis IS NULL)) OR ((mint_started_at_ms IS NOT NULL) AND ((mint_provider_request_millis >= 1) AND (mint_provider_request_millis <= 120000))))),
    CONSTRAINT github_runtime_authority_namespace_shape CHECK ((((octet_length(authority_namespace) >= 1) AND (octet_length(authority_namespace) <= 128)) AND (authority_namespace ~ '^[a-z0-9]([a-z0-9._:/-]*[a-z0-9])?$'::text))),
    CONSTRAINT github_runtime_authority_non_nil_identity CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (lease_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (runner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (runner_session_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (mint_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((revoke_claim_owner_id IS NULL) OR (revoke_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT github_runtime_authority_operation_request_shape CHECK ((((operation_request_kind IS NULL) AND (operation_request_claim_fence IS NULL) AND (operation_request_claim_owner_id IS NULL) AND (operation_request_observed_at_ms IS NULL) AND (operation_request_retry_at_ms IS NULL) AND (operation_request_failure_kind IS NULL) AND (operation_request_commit_disposition IS NULL) AND (operation_request_provider_expires_at_ms IS NULL) AND (operation_request_safe_erase_after_ms IS NULL) AND (operation_request_plaintext_schema IS NULL) AND (operation_request_plaintext_size_bytes IS NULL) AND (operation_request_plaintext_digest IS NULL) AND (operation_request_aad_digest IS NULL) AND (operation_request_envelope_digest IS NULL)) OR ((operation_request_kind = 'mint_commit'::text) AND ((operation_request_claim_fence >= 1) AND (operation_request_claim_fence <= 32)) AND (operation_request_claim_owner_id IS NOT NULL) AND (operation_request_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (operation_request_observed_at_ms >= 0) AND (operation_request_retry_at_ms IS NULL) AND (operation_request_failure_kind IS NULL) AND (operation_request_commit_disposition = ANY (ARRAY['deliverable'::text, 'revoke_only'::text])) AND ((operation_request_provider_expires_at_ms IS NULL) OR (operation_request_provider_expires_at_ms > requested_at_ms)) AND (operation_request_safe_erase_after_ms IS NOT NULL) AND (operation_request_plaintext_schema = 1) AND ((operation_request_plaintext_size_bytes >= 1) AND (operation_request_plaintext_size_bytes <= 65536)) AND (octet_length(operation_request_plaintext_digest) = 32) AND (octet_length(operation_request_aad_digest) = 32) AND (octet_length(operation_request_envelope_digest) = 32)) OR ((operation_request_kind = 'quarantine'::text) AND (operation_request_claim_fence = 0) AND (operation_request_claim_owner_id IS NULL) AND (operation_request_observed_at_ms >= 0) AND (operation_request_retry_at_ms IS NULL) AND (operation_request_failure_kind = ANY (ARRAY['invalid_envelope'::text, 'unsupported_envelope_schema'::text, 'envelope_authentication_failed'::text, 'invalid_wrapped_data_key'::text, 'unknown_wrapping_key'::text, 'retired_wrapping_key'::text, 'cryptographic_failure'::text])) AND (operation_request_commit_disposition IS NULL) AND (operation_request_provider_expires_at_ms IS NULL) AND (operation_request_safe_erase_after_ms IS NULL) AND (operation_request_plaintext_schema IS NULL) AND (operation_request_plaintext_size_bytes IS NULL) AND (operation_request_plaintext_digest IS NULL) AND (octet_length(operation_request_aad_digest) = 32) AND (operation_request_envelope_digest IS NULL)) OR ((operation_request_kind = ANY (ARRAY['revocation_retry'::text, 'revocation_defer'::text, 'revocation_confirm'::text])) AND ((operation_request_claim_fence >= 1) AND (operation_request_claim_fence <= 64)) AND (operation_request_claim_owner_id IS NOT NULL) AND (operation_request_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (operation_request_observed_at_ms >= 0) AND (((operation_request_kind = 'revocation_retry'::text) AND (operation_request_retry_at_ms > operation_request_observed_at_ms) AND (operation_request_failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)) OR ((operation_request_kind = 'revocation_defer'::text) AND (operation_request_retry_at_ms IS NULL) AND (operation_request_failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)) OR ((operation_request_kind = 'revocation_confirm'::text) AND (operation_request_retry_at_ms IS NULL) AND (operation_request_failure_kind IS NULL))) AND ((operation_request_failure_kind IS NULL) OR ((octet_length(operation_request_failure_kind) >= 1) AND (octet_length(operation_request_failure_kind) <= 128))) AND (operation_request_commit_disposition IS NULL) AND (operation_request_provider_expires_at_ms IS NULL) AND (operation_request_safe_erase_after_ms IS NULL) AND (operation_request_plaintext_schema IS NULL) AND (operation_request_plaintext_size_bytes IS NULL) AND (operation_request_plaintext_digest IS NULL) AND (operation_request_aad_digest IS NULL) AND (operation_request_envelope_digest IS NULL)))),
    CONSTRAINT github_runtime_authority_policy_is_job_ir CHECK ((policy_digest = job_ir_digest)),
    CONSTRAINT github_runtime_authority_protected_metadata_complete CHECK ((((safe_erase_after_ms IS NULL) = (commit_disposition IS NULL)) AND ((safe_erase_after_ms IS NULL) = (plaintext_schema IS NULL)) AND ((safe_erase_after_ms IS NULL) = (plaintext_size_bytes IS NULL)) AND ((safe_erase_after_ms IS NULL) = (plaintext_digest IS NULL)) AND ((safe_erase_after_ms IS NULL) = (aad_digest IS NULL)) AND ((provider_expires_at_ms IS NULL) OR (safe_erase_after_ms IS NOT NULL)))),
    CONSTRAINT github_runtime_authority_protected_metadata_shape CHECK (((safe_erase_after_ms IS NULL) OR ((commit_disposition = ANY (ARRAY['deliverable'::text, 'revoke_only'::text])) AND (plaintext_schema = 1) AND ((plaintext_size_bytes >= 1) AND (plaintext_size_bytes <= 65536)) AND (octet_length(plaintext_digest) = 32) AND (octet_length(aad_digest) = 32) AND (((provider_expires_at_ms IS NULL) AND (safe_erase_after_ms = conservative_expiry_at_ms)) OR ((provider_expires_at_ms > requested_at_ms) AND ((provider_expires_at_ms)::numeric <= ((request_deadline_at_ms)::numeric + (3660000)::numeric)) AND ((safe_erase_after_ms)::numeric = ((provider_expires_at_ms)::numeric + (120000)::numeric)) AND (safe_erase_after_ms <= conservative_expiry_at_ms)))))),
    CONSTRAINT github_runtime_authority_provider_installation_positive CHECK ((provider_installation_id > 0)),
    CONSTRAINT github_runtime_authority_quarantine_shape CHECK ((((quarantine_at_ms IS NULL) = (quarantine_kind IS NULL)) AND ((quarantine_kind IS NULL) OR (quarantine_kind = ANY (ARRAY['invalid_envelope'::text, 'unsupported_envelope_schema'::text, 'envelope_authentication_failed'::text, 'invalid_wrapped_data_key'::text, 'unknown_wrapping_key'::text, 'retired_wrapping_key'::text, 'cryptographic_failure'::text]))))),
    CONSTRAINT github_runtime_authority_request_time_shape CHECK (((lease_issued_at_ms >= 0) AND (lease_expires_at_ms > lease_issued_at_ms) AND (requested_at_ms >= lease_issued_at_ms) AND (requested_at_ms < lease_expires_at_ms) AND (request_deadline_at_ms > requested_at_ms) AND (request_deadline_at_ms <= lease_expires_at_ms) AND ((request_deadline_at_ms - requested_at_ms) <= 120000) AND ((conservative_expiry_at_ms)::numeric = ((request_deadline_at_ms)::numeric + (3780000)::numeric)))),
    CONSTRAINT github_runtime_authority_revoke_claim_bounds CHECK ((((revoke_attempt_count >= 0) AND (revoke_attempt_count <= 64)) AND (revoke_claim_fence >= 0) AND ((revoke_claim_owner_id IS NULL) = (revoke_claimed_at_ms IS NULL)) AND ((revoke_claim_owner_id IS NULL) = (revoke_claim_expires_at_ms IS NULL)) AND ((revoke_claim_owner_id IS NULL) OR ((revoke_claim_fence > 0) AND (revoke_attempt_count > 0) AND (revoke_claim_expires_at_ms > revoke_claimed_at_ms) AND ((revoke_claim_expires_at_ms - revoke_claimed_at_ms) <= 120000) AND (revoke_claim_expires_at_ms < safe_erase_after_ms))))),
    CONSTRAINT github_runtime_authority_revoke_failure_shape CHECK (((last_revoke_failure_kind IS NULL) OR (((octet_length(last_revoke_failure_kind) >= 1) AND (octet_length(last_revoke_failure_kind) <= 128)) AND (last_revoke_failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)))),
    CONSTRAINT github_runtime_authority_selection_tail_shape CHECK (((preparation_selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (preparation_selection_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (preparation_selection_generation > 0) AND (octet_length(preparation_selection_descriptor_digest) = 32) AND (preparation_selection_claimed_at_ms >= 0) AND (preparation_selection_expires_at_ms > preparation_selection_claimed_at_ms) AND ((preparation_selection_expires_at_ms - preparation_selection_claimed_at_ms) <= 900000) AND (activation_selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (activation_selection_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (activation_selection_generation > 0) AND (octet_length(activation_selection_input_digest) = 32) AND (activation_selection_claimed_at_ms >= 0) AND (activation_selection_expires_at_ms > activation_selection_claimed_at_ms) AND ((activation_selection_expires_at_ms - activation_selection_claimed_at_ms) <= 900000) AND (materialization_selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (materialization_selection_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (materialization_selection_generation > 0) AND (octet_length(materialization_selection_descriptor_digest) = 32) AND (materialization_selection_claimed_at_ms >= 0) AND (materialization_selection_expires_at_ms > materialization_selection_claimed_at_ms) AND ((materialization_selection_expires_at_ms - materialization_selection_claimed_at_ms) <= 900000))),
    CONSTRAINT github_runtime_authority_state CHECK ((state = ANY (ARRAY['claimed'::text, 'minting'::text, 'mint_retry_pending'::text, 'indeterminate'::text, 'ready'::text, 'revoke_pending'::text, 'quarantined'::text, 'rejected'::text, 'revoked'::text]))),
    CONSTRAINT github_runtime_authority_state_shape CHECK (((((state = 'claimed'::text) AND (mint_claim_expires_at_ms IS NOT NULL) AND (mint_started_at_ms IS NULL) AND (next_mint_at_ms IS NULL) AND (indeterminate_at_ms IS NULL) AND (safe_erase_after_ms IS NULL) AND (envelope_schema IS NULL) AND (ready_at_ms IS NULL) AND (revoke_pending_at_ms IS NULL) AND (rejected_at_ms IS NULL) AND (quarantine_at_ms IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (next_revoke_at_ms IS NULL) AND (last_revoke_failure_kind IS NULL) AND (revoked_at_ms IS NULL) AND (terminal_reason IS NULL) AND (state_updated_at_ms = mint_claimed_at_ms)) OR ((state = 'minting'::text) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms = state_updated_at_ms) AND (next_mint_at_ms IS NULL) AND (indeterminate_at_ms IS NULL) AND (safe_erase_after_ms IS NULL) AND (envelope_schema IS NULL) AND (ready_at_ms IS NULL) AND (revoke_pending_at_ms IS NULL) AND (rejected_at_ms IS NULL) AND (quarantine_at_ms IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (next_revoke_at_ms IS NULL) AND (last_revoke_failure_kind IS NULL) AND (revoked_at_ms IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'mint_retry_pending'::text) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NOT NULL) AND (last_mint_rejection_kind IS NOT NULL) AND (indeterminate_at_ms IS NULL) AND (safe_erase_after_ms IS NULL) AND (envelope_schema IS NULL) AND (ready_at_ms IS NULL) AND (revoke_pending_at_ms IS NULL) AND (rejected_at_ms IS NULL) AND (quarantine_at_ms IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (next_revoke_at_ms IS NULL) AND (last_revoke_failure_kind IS NULL) AND (revoked_at_ms IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'indeterminate'::text) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (indeterminate_at_ms = state_updated_at_ms) AND (safe_erase_after_ms IS NULL) AND (envelope_schema IS NULL) AND (ready_at_ms IS NULL) AND (revoke_pending_at_ms IS NULL) AND (rejected_at_ms IS NULL) AND (quarantine_at_ms IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (next_revoke_at_ms IS NULL) AND (last_revoke_failure_kind IS NULL) AND (revoked_at_ms IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'ready'::text) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (commit_disposition = 'deliverable'::text) AND (provider_expires_at_ms IS NOT NULL) AND ((provider_expires_at_ms)::numeric > ((state_updated_at_ms)::numeric + (60000)::numeric)) AND (envelope_schema IS NOT NULL) AND (ready_at_ms = state_updated_at_ms) AND (revoke_pending_at_ms IS NULL) AND (rejected_at_ms IS NULL) AND (quarantine_at_ms IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (next_revoke_at_ms IS NULL) AND (last_revoke_failure_kind IS NULL) AND (revoked_at_ms IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'revoke_pending'::text) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (safe_erase_after_ms IS NOT NULL) AND (envelope_schema IS NOT NULL) AND (revoke_pending_at_ms IS NOT NULL) AND (rejected_at_ms IS NULL) AND (quarantine_at_ms IS NULL) AND (((revoke_claim_owner_id IS NULL) AND (next_revoke_at_ms IS NOT NULL) AND (next_revoke_at_ms >= revoke_pending_at_ms) AND (next_revoke_at_ms <= safe_erase_after_ms)) OR ((revoke_claim_owner_id IS NOT NULL) AND (next_revoke_at_ms IS NULL))) AND (revoked_at_ms IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'quarantined'::text) AND (mint_claim_expires_at_ms IS NULL) AND (safe_erase_after_ms IS NOT NULL) AND (envelope_schema IS NOT NULL) AND (quarantine_at_ms = state_updated_at_ms) AND (state_updated_at_ms < safe_erase_after_ms) AND (rejected_at_ms IS NULL) AND (revoke_claim_owner_id IS NULL) AND (next_revoke_at_ms IS NULL) AND (revoked_at_ms IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'rejected'::text) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (last_mint_rejection_kind IS NOT NULL) AND (indeterminate_at_ms IS NULL) AND (safe_erase_after_ms IS NULL) AND (envelope_schema IS NULL) AND (ready_at_ms IS NULL) AND (revoke_pending_at_ms IS NULL) AND (rejected_at_ms = state_updated_at_ms) AND (quarantine_at_ms IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (next_revoke_at_ms IS NULL) AND (last_revoke_failure_kind IS NULL) AND (revoked_at_ms IS NULL) AND (terminal_reason = ANY (ARRAY['provider_mint_rejected'::text, 'provider_mint_retry_expired'::text]))) OR ((state = 'revoked'::text) AND (mint_claim_expires_at_ms IS NULL) AND (envelope_schema IS NULL) AND (revoke_claim_owner_id IS NULL) AND (next_revoke_at_ms IS NULL) AND (rejected_at_ms IS NULL) AND (revoked_at_ms = state_updated_at_ms) AND (terminal_reason IS NOT NULL) AND (((terminal_reason = ANY (ARRAY['superseded_before_mint'::text, 'request_expired_before_mint'::text])) AND (mint_started_at_ms IS NULL) AND (indeterminate_at_ms IS NULL) AND (safe_erase_after_ms IS NULL) AND (ready_at_ms IS NULL) AND (revoke_pending_at_ms IS NULL) AND (quarantine_at_ms IS NULL)) OR ((terminal_reason = 'indeterminate_authority_expired'::text) AND (mint_started_at_ms IS NOT NULL) AND (safe_erase_after_ms IS NULL) AND (ready_at_ms IS NULL) AND (revoke_pending_at_ms IS NULL) AND (quarantine_at_ms IS NULL)) OR ((terminal_reason = ANY (ARRAY['provider_revocation_confirmed'::text, 'provider_authority_expired'::text, 'conservative_authority_expired'::text])) AND (mint_started_at_ms IS NOT NULL) AND (safe_erase_after_ms IS NOT NULL) AND ((ready_at_ms IS NOT NULL) OR (revoke_pending_at_ms IS NOT NULL)) AND (quarantine_at_ms IS NULL)) OR ((terminal_reason = 'quarantined_authority_expired'::text) AND (mint_started_at_ms IS NOT NULL) AND (safe_erase_after_ms IS NOT NULL) AND (quarantine_at_ms IS NOT NULL))))) IS TRUE)),
    CONSTRAINT github_runtime_authority_state_time_monotonic CHECK (((state_updated_at_ms >= requested_at_ms) AND ((mint_started_at_ms IS NULL) OR (mint_started_at_ms >= mint_claimed_at_ms)) AND ((indeterminate_at_ms IS NULL) OR (indeterminate_at_ms >= mint_started_at_ms)) AND ((ready_at_ms IS NULL) OR (ready_at_ms >= mint_started_at_ms)) AND ((revoke_pending_at_ms IS NULL) OR (revoke_pending_at_ms >= mint_started_at_ms)) AND ((rejected_at_ms IS NULL) OR (rejected_at_ms >= mint_started_at_ms)) AND ((quarantine_at_ms IS NULL) OR (quarantine_at_ms >= mint_started_at_ms)) AND ((revoked_at_ms IS NULL) OR (revoked_at_ms >= requested_at_ms)))),
    CONSTRAINT github_runtime_authority_terminal_reason CHECK (((terminal_reason IS NULL) OR (terminal_reason = ANY (ARRAY['superseded_before_mint'::text, 'request_expired_before_mint'::text, 'provider_mint_rejected'::text, 'provider_mint_retry_expired'::text, 'provider_revocation_confirmed'::text, 'provider_authority_expired'::text, 'conservative_authority_expired'::text, 'indeterminate_authority_expired'::text, 'quarantined_authority_expired'::text]))))
);

CREATE FUNCTION automata_github_runtime_authority_has_selection_tails(authority github_runtime_authority_issuances) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT EXISTS (
        SELECT 1
        FROM logical_workflow_concrete_jobs AS concrete
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = logical_job.run_id
         AND publication.invocation_id = logical_job.invocation_id
         AND publication.logical_job_id = logical_job.id
         AND publication.activation_input_digest =
             logical_job.activation_input_digest
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = publication.run_id
         AND preparation.invocation_id = publication.invocation_id
         AND preparation.logical_job_id = publication.logical_job_id
         AND preparation.activation_input_digest =
             publication.activation_input_digest
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = preparation.run_id
         AND preparation_claim.invocation_id = preparation.invocation_id
         AND preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.descriptor_digest = preparation.descriptor_digest
        JOIN logical_workflow_activation_work_selections AS preparation_selection
          ON preparation_selection.selection_id =
             authority.preparation_selection_id
         AND preparation_selection.outcome = 'claimed'
         AND preparation_selection.tenant_id = authority.tenant_id
         AND preparation_selection.run_id = authority.run_id
         AND preparation_selection.invocation_id = concrete.invocation_id
         AND preparation_selection.logical_job_id = concrete.logical_job_id
         AND preparation_selection.authority_kind = 'preparation'
         AND preparation_selection.owner_id =
             authority.preparation_selection_owner_id
         AND preparation_selection.authority_digest =
             authority.preparation_selection_descriptor_digest
        JOIN logical_workflow_activation_work_selections AS activation_selection
          ON activation_selection.selection_id = authority.activation_selection_id
         AND activation_selection.outcome = 'claimed'
         AND activation_selection.tenant_id = authority.tenant_id
         AND activation_selection.run_id = authority.run_id
         AND activation_selection.invocation_id = concrete.invocation_id
         AND activation_selection.logical_job_id = concrete.logical_job_id
         AND activation_selection.authority_kind = 'activation'
         AND activation_selection.owner_id = authority.activation_selection_owner_id
         AND activation_selection.authority_digest =
             authority.activation_selection_input_digest
        JOIN logical_workflow_materialization_work_selections AS materialization_selection
          ON materialization_selection.selection_id =
             authority.materialization_selection_id
         AND materialization_selection.outcome = 'claimed'
         AND materialization_selection.tenant_id = authority.tenant_id
         AND materialization_selection.run_id = authority.run_id
         AND materialization_selection.invocation_id = concrete.invocation_id
         AND materialization_selection.logical_job_id = concrete.logical_job_id
         AND materialization_selection.instance_id = concrete.instance_id
         AND materialization_selection.owner_id =
             authority.materialization_selection_owner_id
         AND materialization_selection.authority_digest =
             authority.materialization_selection_descriptor_digest
        WHERE concrete.job_id = authority.job_id
          AND concrete.run_id = authority.run_id
          AND preparation_claim.origin_selection_id =
              authority.preparation_selection_id
          AND preparation_claim.owner_id =
              authority.preparation_selection_owner_id
          AND preparation_claim.generation =
              authority.preparation_selection_generation
          AND preparation_claim.descriptor_digest =
              authority.preparation_selection_descriptor_digest
          AND preparation_claim.claimed_at_ms =
              authority.preparation_selection_claimed_at_ms
          AND preparation_claim.expires_at_ms =
              authority.preparation_selection_expires_at_ms
          AND logical_job.activation_origin_selection_id =
              authority.activation_selection_id
          AND logical_job.activation_fence = authority.activation_selection_generation
          AND logical_job.activation_input_digest =
              authority.activation_selection_input_digest
          AND publication.activation_owner_id =
              authority.activation_selection_owner_id
          AND publication.activation_generation =
              authority.activation_selection_generation
          AND publication.activation_input_digest =
              authority.activation_selection_input_digest
          AND publication.activation_claimed_at_ms =
              authority.activation_selection_claimed_at_ms
          AND publication.activation_expires_at_ms =
              authority.activation_selection_expires_at_ms
          AND materialization.origin_selection_id =
              authority.materialization_selection_id
          AND materialization.owner_id = authority.materialization_selection_owner_id
          AND materialization.generation = authority.materialization_selection_generation
          AND materialization.descriptor_digest =
              authority.materialization_selection_descriptor_digest
          AND materialization.claimed_at_ms =
              authority.materialization_selection_claimed_at_ms
          AND materialization.expires_at_ms =
              authority.materialization_selection_expires_at_ms
          AND (
              (
                  preparation_selection.generation =
                      authority.preparation_selection_generation
                  AND preparation_selection.claimed_at_ms =
                      authority.preparation_selection_claimed_at_ms
                  AND preparation_selection.expires_at_ms =
                      authority.preparation_selection_expires_at_ms
              ) OR EXISTS (
                  SELECT 1
                  FROM logical_workflow_activation_renewal_receipts AS renewal
                  WHERE renewal.selection_id = authority.preparation_selection_id
                    AND renewal.logical_job_id = concrete.logical_job_id
                    AND renewal.authority_kind = 'preparation'
                    AND renewal.owner_id = authority.preparation_selection_owner_id
                    AND renewal.authority_digest =
                        authority.preparation_selection_descriptor_digest
                    AND renewal.runtime_policy_revision =
                        preparation_claim.runtime_policy_revision
                    AND renewal.runtime_policy_digest =
                        preparation_claim.runtime_policy_digest
                    AND renewal.successor_generation =
                        authority.preparation_selection_generation
                    AND renewal.successor_claimed_at_ms =
                        authority.preparation_selection_claimed_at_ms
                    AND renewal.successor_expires_at_ms =
                        authority.preparation_selection_expires_at_ms
              )
          )
          AND (
              (
                  activation_selection.generation =
                      authority.activation_selection_generation
                  AND activation_selection.claimed_at_ms =
                      authority.activation_selection_claimed_at_ms
                  AND activation_selection.expires_at_ms =
                      authority.activation_selection_expires_at_ms
              ) OR EXISTS (
                  SELECT 1
                  FROM logical_workflow_activation_renewal_receipts AS renewal
                  WHERE renewal.selection_id = authority.activation_selection_id
                    AND renewal.logical_job_id = concrete.logical_job_id
                    AND renewal.authority_kind = 'activation'
                    AND renewal.owner_id = authority.activation_selection_owner_id
                    AND renewal.authority_digest =
                        authority.activation_selection_input_digest
                    AND renewal.runtime_policy_revision =
                        logical_job.runtime_policy_revision
                    AND renewal.runtime_policy_digest =
                        logical_job.runtime_policy_digest
                    AND renewal.successor_generation =
                        authority.activation_selection_generation
                    AND renewal.successor_claimed_at_ms =
                        authority.activation_selection_claimed_at_ms
                    AND renewal.successor_expires_at_ms =
                        authority.activation_selection_expires_at_ms
              )
          )
          AND (
              (
                  materialization_selection.generation =
                      authority.materialization_selection_generation
                  AND materialization_selection.claimed_at_ms =
                      authority.materialization_selection_claimed_at_ms
                  AND materialization_selection.expires_at_ms =
                      authority.materialization_selection_expires_at_ms
              ) OR EXISTS (
                  SELECT 1
                  FROM logical_workflow_materialization_renewal_receipts AS renewal
                  WHERE renewal.selection_id = authority.materialization_selection_id
                    AND renewal.instance_id = concrete.instance_id
                    AND renewal.owner_id =
                        authority.materialization_selection_owner_id
                    AND renewal.authority_digest =
                        authority.materialization_selection_descriptor_digest
                    AND renewal.runtime_policy_revision =
                        materialization.runtime_policy_revision
                    AND renewal.runtime_policy_digest =
                        materialization.runtime_policy_digest
                    AND renewal.expected_job_id = concrete.job_id
                    AND renewal.expected_attempt_id = concrete.initial_attempt_id
                    AND renewal.successor_generation =
                        authority.materialization_selection_generation
                    AND renewal.successor_claimed_at_ms =
                        authority.materialization_selection_claimed_at_ms
                    AND renewal.successor_expires_at_ms =
                        authority.materialization_selection_expires_at_ms
              )
          )
    )
$$;

CREATE FUNCTION automata_github_runtime_authority_has_provenance(authority github_runtime_authority_issuances) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT automata_github_runtime_authority_has_selection_tails(authority)
       AND EXISTS (
        SELECT 1
        FROM github_workflow_run_manifest_origins AS origin
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS checks
          ON checks.tenant_id = origin.tenant_id
         AND checks.id = origin.checks_authority_id
         AND checks.repository_id = origin.repository_id
         AND checks.provider_connection_id = origin.provider_connection_id
         AND checks.provider_installation_id = origin.provider_installation_id
         AND checks.github_repository_id = origin.github_repository_id
         AND checks.github_repository_name = origin.github_repository_name
         AND checks.service_scope = 'checks_write'
         AND checks.identity_digest = origin.checks_authority_identity_digest
         AND checks.app_configuration_revision =
             origin.checks_authority_app_configuration_revision
         AND checks.policy_revision = origin.checks_authority_policy_revision
        LEFT JOIN github_server_service_authorities AS private_authority
          ON private_authority.tenant_id = origin.tenant_id
         AND private_authority.id = origin.private_source_authority_id
         AND private_authority.repository_id = origin.repository_id
         AND private_authority.provider_connection_id =
             origin.provider_connection_id
         AND private_authority.provider_installation_id =
             origin.provider_installation_id
         AND private_authority.github_repository_id = origin.github_repository_id
         AND private_authority.github_repository_name =
             origin.github_repository_name
         AND private_authority.service_scope = 'private_repository_source_read'
         AND private_authority.identity_digest =
             origin.private_source_authority_identity_digest
         AND private_authority.app_configuration_revision =
             origin.private_source_authority_app_configuration_revision
         AND private_authority.policy_revision =
             origin.private_source_authority_policy_revision
        JOIN workflow_admission_receipts AS admission
          ON admission.tenant_id = origin.tenant_id
         AND admission.idempotency_kind = origin.admission_idempotency_kind
         AND admission.idempotency_key = origin.admission_idempotency_key
         AND admission.request_digest = origin.logical_admission_digest
         AND admission.repository_id = origin.repository_id
         AND admission.run_id = origin.run_id
         AND admission.committed_at_ms = origin.admitted_at_ms
         AND admission.github_subject_evidence_required
        JOIN logical_workflow_runtime_policy_pins AS pin
          ON pin.run_id = origin.run_id
         AND pin.tenant_id = origin.tenant_id
         AND pin.repository_id = origin.repository_id
        JOIN workflow_runtime_policy_revisions AS policy
          ON policy.tenant_id = pin.tenant_id
         AND policy.repository_id = pin.repository_id
         AND policy.policy_revision = pin.policy_revision
         AND policy.policy_digest = pin.policy_digest
         AND policy.state = 'sealed'
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.job_id = authority.job_id
         AND concrete.run_id = authority.run_id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
         AND materialization.owner_id = concrete.claim_owner_id
         AND materialization.generation = concrete.claim_generation
         AND materialization.claimed_at_ms = concrete.claim_started_at_ms
         AND materialization.expires_at_ms = concrete.claim_expires_at_ms
         AND materialization.updated_at_ms = concrete.committed_at_ms
        JOIN logical_workflow_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN logical_workflow_activation_publications AS activation_publication
          ON activation_publication.run_id = instance.run_id
         AND activation_publication.invocation_id = instance.invocation_id
         AND activation_publication.logical_job_id = instance.logical_job_id
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = activation_publication.run_id
         AND preparation.invocation_id = activation_publication.invocation_id
         AND preparation.logical_job_id = activation_publication.logical_job_id
         AND preparation.activation_input_digest =
             activation_publication.activation_input_digest
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = preparation.run_id
         AND preparation_claim.invocation_id = preparation.invocation_id
         AND preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.descriptor_digest = preparation.descriptor_digest
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = concrete.run_id
         AND invocation.id = concrete.invocation_id
        JOIN logical_workflow_runs AS marker
          ON marker.run_id = concrete.run_id
        WHERE origin.tenant_id = authority.tenant_id
          AND origin.repository_id = authority.repository_id
          AND origin.run_id = authority.run_id
          AND origin.origin_kind IN (
              'provider_delivery', 'scheduled_fire', 'workflow_rerun'
          )
          AND (
              origin.repository_visibility = 'public'
              AND origin.private_source_authority_id IS NULL
              AND private_authority.id IS NULL
              OR origin.repository_visibility = 'private'
              AND private_authority.id IS NOT NULL
              AND private_authority.github_app_id = manifest.github_app_id
              AND private_authority.github_app_client_id =
                  manifest.github_app_client_id
              AND private_authority.github_app_jwt_issuer_kind =
                  manifest.github_app_jwt_issuer_kind
              AND private_authority.app_key_spki_sha256 =
                  manifest.app_key_spki_sha256
              AND private_authority.app_configuration_revision =
                  manifest.app_configuration_revision
              AND private_authority.policy_revision = manifest.policy_revision
          )
          AND origin.provider_connection_id = authority.provider_connection_id
          AND origin.provider_installation_id =
              authority.provider_installation_id
          AND origin.github_repository_id = authority.github_repository_id
          AND origin.github_repository_name = authority.github_repository_name
          AND manifest.github_app_id = authority.github_app_id
          AND manifest.github_app_client_id = authority.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind =
              authority.github_app_jwt_issuer_kind
          AND authority.github_app_jwt_issuer_value =
              CASE manifest.github_app_jwt_issuer_kind
                  WHEN 'app_client_id' THEN manifest.github_app_client_id
                  WHEN 'app_id' THEN manifest.github_app_id::TEXT
              END
          AND manifest.app_key_spki_sha256 = authority.issuer_fingerprint
          AND manifest.github_app_id = checks.github_app_id
          AND manifest.github_app_client_id = checks.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind =
              checks.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = checks.app_key_spki_sha256
          AND manifest.app_configuration_revision =
              checks.app_configuration_revision
          AND manifest.policy_revision = checks.policy_revision
          AND checks.configuration_fingerprint =
              authority.configuration_fingerprint
          AND marker.root_invocation_id = origin.root_invocation_id
          AND marker.admission_digest = origin.logical_admission_digest
          AND marker.admitted_at_ms = origin.admitted_at_ms
          AND automata_logical_workflow_invocation_published(
              concrete.run_id, concrete.invocation_id
          )
          AND invocation.plan_schema = 1
          AND manifest.runtime_policy_revision = pin.policy_revision
          AND manifest.runtime_policy_digest = pin.policy_digest
          AND manifest.runner_policy_digest =
              pg_catalog.sha256(policy.canonical_policy)
          AND manifest.runner_policy_object_key = 'github/runner-policy/v1/'
              || pg_catalog.encode(manifest.runner_policy_digest, 'hex') || '.json'
          AND manifest.runner_policy_size_bytes =
              pg_catalog.octet_length(policy.canonical_policy)
          AND manifest.runner_policy_media_type =
              'application/vnd.automata.github-runner-policy+json'
          AND logical_job.runtime_policy_revision = pin.policy_revision
          AND logical_job.runtime_policy_digest = pin.policy_digest
          AND preparation_claim.runtime_policy_revision = pin.policy_revision
          AND preparation_claim.runtime_policy_digest = pin.policy_digest
          AND preparation_claim.runner_policy_digest =
              manifest.runner_policy_digest
          AND preparation_claim.runner_policy_object_key =
              manifest.runner_policy_object_key
          AND preparation_claim.runner_policy_size_bytes =
              manifest.runner_policy_size_bytes
          AND preparation_claim.runner_policy_media_type =
              manifest.runner_policy_media_type
          AND preparation.runtime_policy_revision = pin.policy_revision
          AND preparation.runtime_policy_digest = pin.policy_digest
          AND activation_publication.runtime_policy_revision = pin.policy_revision
          AND activation_publication.runtime_policy_digest = pin.policy_digest
          AND instance.runtime_policy_revision = pin.policy_revision
          AND instance.runtime_policy_digest = pin.policy_digest
          AND materialization.runtime_policy_revision = pin.policy_revision
          AND materialization.runtime_policy_digest = pin.policy_digest
          AND concrete.runtime_policy_revision = pin.policy_revision
          AND concrete.runtime_policy_digest = pin.policy_digest
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND activation_publication.authority_profile = 'standard'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
    )
$$;
