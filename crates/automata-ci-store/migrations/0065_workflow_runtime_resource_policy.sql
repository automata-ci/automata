-- Add repository-pinned resource defaults and bounds to runtime policy.
--
-- Migration 0043 is already a released SQLx migration and must remain byte
-- stable. Its schema-1 policy did not carry enough evidence to infer resource
-- defaults or limits. Inventing that evidence would silently change historical
-- policy identities, so this forward migration accepts only an empty policy
-- catalog. Operators with historical policies must explicitly drain that
-- current-only state before retrying the migration.

LOCK TABLE workflow_runtime_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM workflow_runtime_policy_revisions) THEN
        RAISE EXCEPTION 'pre-resource workflow runtime policies must be explicitly drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_resource_policy_current_only';
    END IF;
END;
$automata$;
ALTER TABLE workflow_runtime_policy_revisions
    ADD COLUMN resource_policy_canonical BYTEA NOT NULL,
    DROP CONSTRAINT workflow_runtime_policy_revisions_identity,
    ADD CONSTRAINT workflow_runtime_policy_revisions_identity CHECK (
        repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND policy_revision > 0
        AND octet_length(policy_digest) = 32
        AND policy_schema = 1
        AND octet_length(resource_policy_canonical) BETWEEN 1 AND 8192
    );

CREATE FUNCTION automata_workflow_runtime_resource_policy_digest(BYTEA)
RETURNS BYTEA
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
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
           mapping_count, resource_policy_canonical
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
               string_agg(
                   encoded,
                   pg_catalog.decode('', 'hex') ORDER BY selector
               ),
               pg_catalog.decode('', 'hex')
           ) AS encoded
    FROM mapping_parts
)
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.workflow-runtime-policy.v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || pg_catalog.int2send(header.policy_schema)
    || pg_catalog.int2send(header.workspace_derivation_version)
    || automata_workflow_runtime_policy_digest_part(
        pg_catalog.convert_to(header.workspace_root, 'UTF8')
    )
    || pg_catalog.int8send(header.mapping_count::BIGINT)
    || catalog.encoded
    || automata_workflow_runtime_resource_policy_digest(
        header.resource_policy_canonical
    )
)
FROM header CROSS JOIN catalog
WHERE header.policy_schema = 1
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
           mapping_count, resource_policy_canonical
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
    || catalog.encoded || '],"resources":'
    || pg_catalog.convert_from(header.resource_policy_canonical, 'UTF8')
    || '}',
    'UTF8'
)
FROM header CROSS JOIN catalog
WHERE header.policy_schema = 1
  AND header.workspace_root = '/__w'
  AND header.workspace_derivation_version = 1
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
