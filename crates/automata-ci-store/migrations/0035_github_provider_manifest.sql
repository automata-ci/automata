-- Current-only immutable GitHub provider manifest.
--
-- Static configuration proposes a complete non-secret revision at startup.
-- Exactly one pointer is current for each stable connection; prior revisions
-- remain immutable and readable for later delivery/Check pinning.

-- Deliveries or Check subjects created before manifest pinning cannot be
-- assigned trustworthy policy evidence. This is pre-release state and must be
-- explicitly drained instead of guessed or backfilled.
--
-- SHARE ROW EXCLUSIVE conflicts with ordinary INSERT/UPDATE/DELETE writers.
-- Holding both locks through the audit and trigger installation closes the
-- audit-to-commit race: an earlier writer is visible to the audit, while a
-- later writer resumes only after the fail-closed triggers are committed.
LOCK TABLE provider_delivery_inbox IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE github_check_subjects IN SHARE ROW EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1 FROM provider_delivery_inbox WHERE provider = 'github'
    ) OR EXISTS (
        SELECT 1 FROM github_check_subjects
    ) THEN
        RAISE EXCEPTION 'pre-manifest GitHub deliveries and Check subjects must be explicitly drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_current_only';
    END IF;
END;
$automata$;

-- These two guards are intentionally temporary capability gates. They may be
-- dropped only by the future migration that adds mandatory manifest pins and
-- atomically creates a delivery, its queued Check subject, and their exact
-- manifest revision evidence in one transaction. Removing them independently
-- would reopen an unpinned-state race.
CREATE FUNCTION automata_github_provider_manifest_reject_unpinned_delivery()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.provider = 'github' THEN
        RAISE EXCEPTION 'GitHub deliveries require atomic provider-manifest pinning'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_unpinned_delivery_forbidden';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER provider_delivery_inbox_00_require_github_manifest_pin
BEFORE INSERT ON provider_delivery_inbox
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_manifest_reject_unpinned_delivery();

COMMENT ON TRIGGER provider_delivery_inbox_00_require_github_manifest_pin
ON provider_delivery_inbox IS
'Interim fail-closed gate; replace only with mandatory atomic manifest pinning.';

CREATE FUNCTION automata_github_provider_manifest_reject_unpinned_check()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub Check subjects require atomic provider-manifest pinning'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_provider_manifest_unpinned_check_forbidden';
END;
$automata$;

CREATE TRIGGER github_check_subjects_00_00_require_manifest_pin
BEFORE INSERT ON github_check_subjects
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_manifest_reject_unpinned_check();

COMMENT ON TRIGGER github_check_subjects_00_00_require_manifest_pin
ON github_check_subjects IS
'Interim fail-closed gate; replace only with mandatory atomic manifest pinning.';

-- PostgreSQL provides sha256(bytea) in pg_catalog; no pgcrypto extension or
-- extension-creation privilege is required by this migration or at runtime.
CREATE FUNCTION automata_github_provider_manifest_digest_part(BYTEA)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.int8send(pg_catalog.octet_length($1)::BIGINT) || $1
$automata$;

CREATE FUNCTION automata_github_provider_repository_id(TEXT, BIGINT)
RETURNS UUID
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
WITH raw(bytes) AS (
    SELECT substring(
        pg_catalog.sha256(
            pg_catalog.convert_to('automata.admission.repository.v1', 'UTF8')
            || pg_catalog.decode('00', 'hex')
            || automata_github_provider_manifest_digest_part(
                pg_catalog.convert_to($1, 'UTF8')
            )
            || automata_github_provider_manifest_digest_part(
                pg_catalog.convert_to('github', 'UTF8')
            )
            || automata_github_provider_manifest_digest_part(
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
$automata$;

CREATE TABLE github_provider_manifest_revisions (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    manifest_revision BIGINT NOT NULL,
    manifest_digest BYTEA NOT NULL,
    provider_installation_id BIGINT NOT NULL,
    github_repository_id BIGINT NOT NULL,
    github_repository_name TEXT COLLATE "C" NOT NULL,
    repository_visibility TEXT COLLATE "C" NOT NULL,
    github_app_id BIGINT NOT NULL,
    github_app_client_id TEXT COLLATE "C" NOT NULL,
    github_app_jwt_issuer_kind TEXT COLLATE "C" NOT NULL,
    app_key_spki_sha256 BYTEA NOT NULL,
    app_configuration_revision BIGINT NOT NULL,
    webhook_verifier_fingerprint_sha256 BYTEA NOT NULL,
    webhook_verifier_revision BIGINT NOT NULL,
    policy_revision BIGINT NOT NULL,
    workflow_path TEXT COLLATE "C" NOT NULL,
    event_name TEXT COLLATE "C" NOT NULL,
    git_ref TEXT COLLATE "C" NOT NULL,
    check_subject_key TEXT COLLATE "C" NOT NULL,
    check_name TEXT COLLATE "C" NOT NULL,
    github_web_origin TEXT COLLATE "C" NOT NULL,
    github_api_origin TEXT COLLATE "C" NOT NULL,
    github_archive_origin TEXT COLLATE "C" NOT NULL,
    github_rest_api_version TEXT COLLATE "C" NOT NULL,
    github_rest_accept TEXT COLLATE "C" NOT NULL,
    github_archive_accept TEXT COLLATE "C" NOT NULL,
    repository_source_authentication TEXT COLLATE "C" NOT NULL,
    repository_source_revision TEXT COLLATE "C" NOT NULL,
    repository_archive_format TEXT COLLATE "C" NOT NULL,
    webhook_max_body_bytes BIGINT NOT NULL,
    webhook_accept_timeout_ms BIGINT NOT NULL,
    push_webhook_max_commits BIGINT NOT NULL,
    path_filter_max_commits BIGINT NOT NULL,
    path_filter_max_changed_files BIGINT NOT NULL,
    archive_max_compressed_bytes BIGINT NOT NULL,
    archive_max_decompressed_bytes BIGINT NOT NULL,
    archive_max_entries BIGINT NOT NULL,
    archive_max_expanded_bytes BIGINT NOT NULL,
    archive_max_entry_path_bytes BIGINT NOT NULL,
    archive_max_workflows BIGINT NOT NULL,
    workflow_max_bytes BIGINT NOT NULL,
    registered_at_ms BIGINT NOT NULL,

    CONSTRAINT github_provider_manifest_revisions_primary_key PRIMARY KEY (
        provider_connection_id, manifest_revision
    ),
    CONSTRAINT github_provider_manifest_revisions_tenant_key_unique UNIQUE (
        tenant_id, provider_connection_id, manifest_revision
    ),
    CONSTRAINT github_provider_manifest_revisions_exact_key_unique UNIQUE (
        tenant_id, repository_id, provider_connection_id,
        manifest_revision, manifest_digest
    ),
    CONSTRAINT github_provider_manifest_revisions_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_provider_manifest_revisions_non_nil CHECK (
        repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND provider_connection_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT github_provider_manifest_revisions_positive CHECK (
        manifest_revision > 0
        AND provider_installation_id > 0
        AND github_repository_id > 0
        AND github_app_id > 0
        AND app_configuration_revision > 0
        AND webhook_verifier_revision > 0
        AND policy_revision > 0
    ),
    CONSTRAINT github_provider_manifest_revisions_digest_shape CHECK (
        octet_length(manifest_digest) = 32
        AND octet_length(app_key_spki_sha256) = 32
        AND octet_length(webhook_verifier_fingerprint_sha256) = 32
        AND webhook_verifier_fingerprint_sha256
            <> pg_catalog.decode(repeat('00', 32), 'hex')
    ),
    CONSTRAINT github_provider_manifest_revisions_repository_name CHECK (
        array_length(string_to_array(github_repository_name, '/'), 1) = 2
        AND octet_length(split_part(github_repository_name, '/', 1)) BETWEEN 1 AND 39
        AND split_part(github_repository_name, '/', 1)
            ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$'
        AND split_part(github_repository_name, '/', 1) !~ '--'
        AND octet_length(split_part(github_repository_name, '/', 2)) BETWEEN 1 AND 100
        AND split_part(github_repository_name, '/', 2) ~ '^[A-Za-z0-9._-]+$'
        AND split_part(github_repository_name, '/', 2) NOT IN ('.', '..')
        AND split_part(github_repository_name, '/', 2) !~* '[.]git$'
    ),
    CONSTRAINT github_provider_manifest_revisions_visibility_exact CHECK (
        repository_visibility IN ('public', 'private')
    ),
    CONSTRAINT github_provider_manifest_revisions_app_client_shape CHECK (
        octet_length(github_app_client_id) BETWEEN 1 AND 128
        AND github_app_client_id ~ '^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$'
    ),
    CONSTRAINT github_provider_manifest_revisions_jwt_issuer CHECK (
        github_app_jwt_issuer_kind IN ('app_client_id', 'app_id')
    ),
    CONSTRAINT github_provider_manifest_revisions_selector_exact CHECK (
        workflow_path = '.github/workflows/ci.yml'
        AND event_name = 'push'
        AND git_ref = 'refs/heads/main'
        AND check_subject_key = workflow_path
    ),
    CONSTRAINT github_provider_manifest_revisions_check_name_shape CHECK (
        octet_length(check_name) BETWEEN 1 AND 255
        AND btrim(check_name) = check_name
        AND check_name !~ '[^ -~]'
    ),
    CONSTRAINT github_provider_manifest_revisions_origins_exact CHECK (
        github_web_origin = 'https://github.com/'
        AND github_api_origin = 'https://api.github.com/'
        AND github_archive_origin = 'https://codeload.github.com/'
    ),
    CONSTRAINT github_provider_manifest_revisions_provider_semantics_exact CHECK (
        github_rest_api_version = '2026-03-10'
        AND github_rest_accept = 'application/vnd.github+json'
        AND github_archive_accept = 'application/octet-stream'
        AND (
            (
                repository_visibility = 'public'
                AND repository_source_authentication = 'anonymous_public'
            ) OR (
                repository_visibility = 'private'
                AND repository_source_authentication = 'github_app_installation_token'
            )
        )
        AND repository_source_revision = 'exact_sha'
        AND repository_archive_format = 'tar_gzip'
    ),
    CONSTRAINT github_provider_manifest_revisions_webhook_limits CHECK (
        webhook_max_body_bytes = 26214400
        AND webhook_accept_timeout_ms = 7000
        AND push_webhook_max_commits = 2048
        AND path_filter_max_commits = 1000
        AND path_filter_max_changed_files = 3000
    ),
    CONSTRAINT github_provider_manifest_revisions_archive_limits CHECK (
        archive_max_compressed_bytes = 268435456
        AND archive_max_decompressed_bytes = 2147483648
        AND archive_max_entries = 100000
        AND archive_max_expanded_bytes = 1073741824
        AND archive_max_entry_path_bytes = 4096
        AND archive_max_workflows = 256
        AND workflow_max_bytes = 1048576
    ),
    CONSTRAINT github_provider_manifest_revisions_time CHECK (
        registered_at_ms >= 0
    )
);

CREATE FUNCTION automata_github_provider_manifest_digest(
    github_provider_manifest_revisions
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.github-provider-manifest.v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).tenant_id, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(($1).repository_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(($1).provider_connection_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).provider_installation_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).github_repository_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).github_repository_name, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).repository_visibility, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).github_app_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).github_app_client_id, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).github_app_jwt_issuer_kind, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(($1).app_key_spki_sha256)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).app_configuration_revision)
    )
    || automata_github_provider_manifest_digest_part(
        ($1).webhook_verifier_fingerprint_sha256
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).webhook_verifier_revision)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).policy_revision)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).manifest_revision)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).workflow_path, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).event_name, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).git_ref, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).check_subject_key, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).check_name, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).github_web_origin, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).github_api_origin, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).github_archive_origin, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).github_rest_api_version, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).github_rest_accept, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).github_archive_accept, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).repository_source_authentication, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).repository_source_revision, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(($1).repository_archive_format, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).webhook_max_body_bytes)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).webhook_accept_timeout_ms)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).push_webhook_max_commits)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).path_filter_max_commits)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).path_filter_max_changed_files)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).archive_max_compressed_bytes)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).archive_max_decompressed_bytes)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).archive_max_entries)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).archive_max_expanded_bytes)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).archive_max_entry_path_bytes)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).archive_max_workflows)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(($1).workflow_max_bytes)
    )
)
$automata$;

ALTER TABLE github_provider_manifest_revisions
ADD CONSTRAINT github_provider_manifest_revisions_repository_id_canonical CHECK (
    repository_id = automata_github_provider_repository_id(
        tenant_id,
        github_repository_id
    )
),
ADD CONSTRAINT github_provider_manifest_revisions_digest_canonical CHECK (
    manifest_digest = automata_github_provider_manifest_digest(
        github_provider_manifest_revisions
    )
);

CREATE FUNCTION automata_github_provider_manifest_canonical_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER github_provider_manifest_revisions_00_canonical_guard
BEFORE INSERT ON github_provider_manifest_revisions
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_manifest_canonical_guard();

CREATE TABLE github_provider_manifest_current (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID PRIMARY KEY,
    manifest_revision BIGINT NOT NULL,
    manifest_digest BYTEA NOT NULL,
    activated_at_ms BIGINT NOT NULL,

    CONSTRAINT github_provider_manifest_current_repository_unique UNIQUE (
        tenant_id, repository_id
    ),
    CONSTRAINT github_provider_manifest_current_exact_revision
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        ) REFERENCES github_provider_manifest_revisions(
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        ) ON DELETE RESTRICT,
    CONSTRAINT github_provider_manifest_current_non_nil CHECK (
        repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND provider_connection_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT github_provider_manifest_current_shape CHECK (
        manifest_revision > 0
        AND octet_length(manifest_digest) = 32
        AND activated_at_ms >= 0
    )
);

CREATE FUNCTION automata_github_provider_manifest_repository_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER github_provider_manifest_revisions_repository_exact
BEFORE INSERT ON github_provider_manifest_revisions
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_manifest_repository_exact();

CREATE FUNCTION automata_github_provider_manifest_repository_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER repositories_github_provider_manifest_identity_immutable
BEFORE UPDATE ON repositories
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_manifest_repository_identity_immutable();

CREATE FUNCTION automata_github_provider_manifest_revision_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub provider manifest revisions are immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_provider_manifest_revisions_immutable';
END;
$automata$;

CREATE TRIGGER github_provider_manifest_revisions_no_update
BEFORE UPDATE OR DELETE ON github_provider_manifest_revisions
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_manifest_revision_immutable();

CREATE TRIGGER github_provider_manifest_revisions_no_truncate
BEFORE TRUNCATE ON github_provider_manifest_revisions
FOR EACH STATEMENT
EXECUTE FUNCTION automata_github_provider_manifest_revision_immutable();

CREATE FUNCTION automata_github_provider_manifest_current_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    prior github_provider_manifest_revisions%ROWTYPE;
    replacement github_provider_manifest_revisions%ROWTYPE;
    app_evidence_changed BOOLEAN;
    verifier_evidence_changed BOOLEAN;
    policy_evidence_changed BOOLEAN;
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
        OR (CASE
            WHEN OLD.manifest_revision = 9223372036854775807 THEN TRUE
            ELSE NEW.manifest_revision <> OLD.manifest_revision + 1
        END)
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

    app_evidence_changed =
        replacement.app_key_spki_sha256 IS DISTINCT FROM prior.app_key_spki_sha256;
    verifier_evidence_changed =
        replacement.webhook_verifier_fingerprint_sha256
            IS DISTINCT FROM prior.webhook_verifier_fingerprint_sha256;
    policy_evidence_changed =
        replacement.repository_visibility IS DISTINCT FROM prior.repository_visibility
        OR replacement.workflow_path IS DISTINCT FROM prior.workflow_path
        OR replacement.event_name IS DISTINCT FROM prior.event_name
        OR replacement.git_ref IS DISTINCT FROM prior.git_ref
        OR replacement.check_subject_key IS DISTINCT FROM prior.check_subject_key
        OR replacement.check_name IS DISTINCT FROM prior.check_name
        OR replacement.github_rest_api_version IS DISTINCT FROM prior.github_rest_api_version
        OR replacement.github_rest_accept IS DISTINCT FROM prior.github_rest_accept
        OR replacement.github_archive_accept IS DISTINCT FROM prior.github_archive_accept
        OR replacement.repository_source_authentication
            IS DISTINCT FROM prior.repository_source_authentication
        OR replacement.repository_source_revision IS DISTINCT FROM prior.repository_source_revision
        OR replacement.repository_archive_format IS DISTINCT FROM prior.repository_archive_format
        OR replacement.webhook_max_body_bytes IS DISTINCT FROM prior.webhook_max_body_bytes
        OR replacement.webhook_accept_timeout_ms IS DISTINCT FROM prior.webhook_accept_timeout_ms
        OR replacement.push_webhook_max_commits IS DISTINCT FROM prior.push_webhook_max_commits
        OR replacement.path_filter_max_commits IS DISTINCT FROM prior.path_filter_max_commits
        OR replacement.path_filter_max_changed_files
            IS DISTINCT FROM prior.path_filter_max_changed_files
        OR replacement.archive_max_compressed_bytes IS DISTINCT FROM prior.archive_max_compressed_bytes
        OR replacement.archive_max_decompressed_bytes IS DISTINCT FROM prior.archive_max_decompressed_bytes
        OR replacement.archive_max_entries IS DISTINCT FROM prior.archive_max_entries
        OR replacement.archive_max_expanded_bytes IS DISTINCT FROM prior.archive_max_expanded_bytes
        OR replacement.archive_max_entry_path_bytes IS DISTINCT FROM prior.archive_max_entry_path_bytes
        OR replacement.archive_max_workflows IS DISTINCT FROM prior.archive_max_workflows
        OR replacement.workflow_max_bytes IS DISTINCT FROM prior.workflow_max_bytes;

    IF NOT (app_evidence_changed OR verifier_evidence_changed OR policy_evidence_changed)
        OR (CASE
            WHEN app_evidence_changed THEN
                prior.app_configuration_revision = 9223372036854775807
                OR replacement.app_configuration_revision
                    <> prior.app_configuration_revision + 1
            ELSE replacement.app_configuration_revision
                <> prior.app_configuration_revision
        END)
        OR (CASE
            WHEN verifier_evidence_changed THEN
                prior.webhook_verifier_revision = 9223372036854775807
                OR replacement.webhook_verifier_revision
                    <> prior.webhook_verifier_revision + 1
            ELSE replacement.webhook_verifier_revision
                <> prior.webhook_verifier_revision
        END)
        OR (CASE
            WHEN policy_evidence_changed THEN
                prior.policy_revision = 9223372036854775807
                OR replacement.policy_revision <> prior.policy_revision + 1
            ELSE replacement.policy_revision <> prior.policy_revision
        END)
    THEN
        RAISE EXCEPTION 'GitHub provider manifest policy revision did not advance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_revision_transition';
    END IF;

    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_provider_manifest_current_guard
BEFORE INSERT OR UPDATE OR DELETE ON github_provider_manifest_current
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_manifest_current_guard();

CREATE FUNCTION automata_github_provider_manifest_current_no_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub provider manifest current pointers cannot be truncated'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_provider_manifest_current_removal_forbidden';
END;
$automata$;

CREATE TRIGGER github_provider_manifest_current_no_truncate
BEFORE TRUNCATE ON github_provider_manifest_current
FOR EACH STATEMENT
EXECUTE FUNCTION automata_github_provider_manifest_current_no_truncate();
