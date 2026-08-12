-- Add exact repository-pinned expansions for GitHub permission shorthands.
--
-- Schema-1 policies did not identify repository defaults or the provider
-- permission universe behind read-all/write-all. That evidence cannot be
-- reconstructed safely, so this current-only migration accepts an empty
-- catalog and advances the immutable runtime-policy contract to schema 2.

LOCK TABLE workflow_runtime_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM workflow_runtime_policy_revisions) THEN
        RAISE EXCEPTION 'pre-permission workflow runtime policies must be explicitly drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_permission_policy_current_only';
    END IF;
END;
$automata$;

ALTER TABLE workflow_runtime_policy_revisions
    ADD COLUMN permission_policy_canonical BYTEA NOT NULL,
    DROP CONSTRAINT workflow_runtime_policy_revisions_identity,
    ADD CONSTRAINT workflow_runtime_policy_revisions_identity CHECK (
        repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND policy_revision > 0
        AND octet_length(policy_digest) = 32
        AND policy_schema = 2
        AND octet_length(permission_policy_canonical) BETWEEN 1 AND 32768
        AND octet_length(resource_policy_canonical) BETWEEN 1 AND 8192
    );

CREATE FUNCTION automata_workflow_runtime_permission_policy_digest(BYTEA)
RETURNS BYTEA
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
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
                || automata_workflow_runtime_policy_digest_part(
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
$automata$;

CREATE OR REPLACE FUNCTION automata_workflow_runtime_policy_digest(TEXT, UUID, BIGINT)
RETURNS BYTEA
LANGUAGE SQL
STABLE
STRICT
PARALLEL SAFE
AS $automata$
WITH header AS (
    SELECT policy_schema, workspace_root, workspace_derivation_version,
           mapping_count, permission_policy_canonical, resource_policy_canonical
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = $3
), mapping_parts AS (
    SELECT mapping.selector,
           automata_workflow_runtime_policy_digest_part(
               pg_catalog.convert_to(mapping.selector, 'UTF8')
           )
           || automata_workflow_runtime_policy_digest_part(
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
                    automata_workflow_runtime_policy_digest_part(
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
    || automata_workflow_runtime_policy_digest_part(
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
WHERE header.policy_schema = 2
  AND automata_workflow_runtime_permission_policy_digest(
      header.permission_policy_canonical
  ) IS NOT NULL
  AND automata_workflow_runtime_resource_policy_digest(
      header.resource_policy_canonical
  ) IS NOT NULL
  AND header.mapping_count = catalog.actual_mapping_count
  AND catalog.features_exact IS TRUE
$automata$;

CREATE OR REPLACE FUNCTION automata_workflow_runtime_policy_canonical(TEXT, UUID, BIGINT)
RETURNS BYTEA
LANGUAGE SQL
STABLE
STRICT
PARALLEL SAFE
AS $automata$
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
    '{"schema":2,"workspace":{"schema":1,"root":"/__w","derivation":1},"mappings":['
    || catalog.encoded || '],"permissions":'
    || pg_catalog.convert_from(header.permission_policy_canonical, 'UTF8')
    || ',"resources":'
    || pg_catalog.convert_from(header.resource_policy_canonical, 'UTF8')
    || '}',
    'UTF8'
)
FROM header CROSS JOIN catalog
WHERE header.policy_schema = 2
  AND header.workspace_root = '/__w'
  AND header.workspace_derivation_version = 1
  AND automata_workflow_runtime_permission_policy_digest(
      header.permission_policy_canonical
  ) IS NOT NULL
  AND header.mapping_count = catalog.actual_mapping_count
  AND catalog.features_exact IS TRUE
$automata$;

CREATE OR REPLACE FUNCTION automata_enforce_workflow_runtime_policy_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    actual_digest BYTEA;
    actual_canonical BYTEA;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'staging' OR NEW.sealed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'workflow runtime policy must be inserted as staging'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_runtime_policy_insert_staging';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
        OR NEW.policy_digest IS DISTINCT FROM OLD.policy_digest
        OR NEW.canonical_policy IS DISTINCT FROM OLD.canonical_policy
        OR NEW.permission_policy_canonical IS DISTINCT FROM OLD.permission_policy_canonical
        OR NEW.resource_policy_canonical IS DISTINCT FROM OLD.resource_policy_canonical
        OR NEW.policy_schema IS DISTINCT FROM OLD.policy_schema
        OR NEW.workspace_root IS DISTINCT FROM OLD.workspace_root
        OR NEW.workspace_derivation_version IS DISTINCT FROM OLD.workspace_derivation_version
        OR NEW.mapping_count IS DISTINCT FROM OLD.mapping_count
        OR OLD.state <> 'staging'
        OR NEW.state <> 'sealed'
        OR NEW.registered_at_ms IS DISTINCT FROM OLD.registered_at_ms
        OR NEW.sealed_at_ms IS DISTINCT FROM NEW.registered_at_ms
    THEN
        RAISE EXCEPTION 'workflow runtime policy revision is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_revision_immutable';
    END IF;

    actual_digest := automata_workflow_runtime_policy_digest(
        NEW.tenant_id, NEW.repository_id, NEW.policy_revision
    );
    IF actual_digest IS NULL OR actual_digest IS DISTINCT FROM NEW.policy_digest THEN
        RAISE EXCEPTION 'workflow runtime policy content digest is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_digest_exact';
    END IF;
    actual_canonical := automata_workflow_runtime_policy_canonical(
        NEW.tenant_id, NEW.repository_id, NEW.policy_revision
    );
    IF actual_canonical IS NULL
        OR actual_canonical IS DISTINCT FROM NEW.canonical_policy
        OR pg_catalog.octet_length(actual_canonical) NOT BETWEEN 1 AND 65536
    THEN
        RAISE EXCEPTION 'workflow runtime policy canonical object is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_canonical_exact';
    END IF;
    RETURN NEW;
END;
$automata$;
