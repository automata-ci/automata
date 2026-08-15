-- Wave 1 capability-policy append-only migration 0046. Earlier applied versions remain frozen.

ALTER TABLE workflow_runtime_policy_mappings
    ADD COLUMN runner_feature_schema smallint,
    ADD COLUMN runner_feature_count integer NOT NULL DEFAULT 0;

ALTER TABLE workflow_runtime_policy_mappings
    ALTER COLUMN runner_feature_count DROP DEFAULT,
    ADD CONSTRAINT workflow_runtime_policy_mappings_runner_features CHECK (
        (runner_feature_schema IS NULL AND runner_feature_count = 0)
        OR (runner_feature_schema = 1 AND runner_feature_count BETWEEN 0 AND 64)
    );

ALTER TABLE workflow_runtime_policy_revisions
    DROP CONSTRAINT workflow_runtime_policy_revisions_identity,
    ADD CONSTRAINT workflow_runtime_policy_revisions_identity CHECK (
        repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND policy_revision > 0
        AND octet_length(policy_digest) = 32
        AND policy_schema IN (1, 2)
        AND octet_length(permission_policy_canonical) BETWEEN 1 AND 32768
        AND octet_length(resource_policy_canonical) BETWEEN 1 AND 8192
    );

CREATE TABLE workflow_runtime_policy_runner_features (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    selector text NOT NULL COLLATE pg_catalog."C",
    feature text NOT NULL COLLATE pg_catalog."C",
    CONSTRAINT workflow_runtime_policy_runner_features_shape CHECK (
        octet_length(feature) BETWEEN 1 AND 128
        AND feature IN (
            'automata.core/shell-steps@v1',
            'automata.core/default-posix-shell@v1',
            'automata.core/default-windows-shell@v1',
            'automata.core/bash-shell@v1',
            'automata.core/sh-shell@v1',
            'automata.core/python-shell@v1',
            'automata.core/pwsh-shell@v1',
            'automata.core/windows-powershell-shell@v1',
            'automata.core/cmd-shell@v1',
            'automata.core/javascript-actions@v1',
            'automata.core/node12-actions@v1',
            'automata.core/node16-actions@v1',
            'automata.core/node20-actions@v1',
            'automata.core/node24-actions@v1',
            'automata.core/composite-actions@v1',
            'automata.core/repository-actions@v1',
            'automata.core/local-actions@v1',
            'automata.core/command-files@v1',
            'automata.core/job-summaries@v1',
            'automata.core/oidc-tokens@v1'
        )
        AND CASE
            WHEN feature ~ '^[a-z]([a-z0-9-]*[a-z0-9])?(\.[a-z]([a-z0-9-]*[a-z0-9])?)*/[a-z]([a-z0-9-]*[a-z0-9])?@v[1-9][0-9]{0,4}$'
            THEN substring(feature, '@v([1-9][0-9]{0,4})$')::integer BETWEEN 1 AND 65535
            ELSE false
        END
    ),
    CONSTRAINT workflow_runtime_policy_runner_features_pk PRIMARY KEY (
        tenant_id, repository_id, policy_revision, selector, feature
    ),
    CONSTRAINT workflow_runtime_policy_runner_features_mapping_fk FOREIGN KEY (
        tenant_id, repository_id, policy_revision, selector
    ) REFERENCES workflow_runtime_policy_mappings (
        tenant_id, repository_id, policy_revision, selector
    ) ON DELETE RESTRICT
);

CREATE FUNCTION automata_require_staging_workflow_runtime_runner_feature() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_state text;
    declared_schema smallint;
    declared_count integer;
    inserted_count integer;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'workflow runtime policy runner features are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_runner_features_immutable';
    END IF;

    SELECT state INTO parent_state
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND policy_revision = NEW.policy_revision
    FOR UPDATE;
    IF parent_state IS DISTINCT FROM 'staging' THEN
        RAISE EXCEPTION 'workflow runtime policy catalog is sealed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_catalog_sealed';
    END IF;

    SELECT runner_feature_schema, runner_feature_count
    INTO declared_schema, declared_count
    FROM workflow_runtime_policy_mappings
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND policy_revision = NEW.policy_revision
      AND selector = NEW.selector
    FOR UPDATE;

    SELECT count(*)::integer INTO inserted_count
    FROM workflow_runtime_policy_runner_features
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND policy_revision = NEW.policy_revision
      AND selector = NEW.selector;

    IF declared_schema IS DISTINCT FROM 1
        OR declared_count IS NULL
        OR inserted_count >= declared_count
        OR inserted_count >= 64
    THEN
        RAISE EXCEPTION 'workflow runtime policy runner feature census exceeded'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_runner_feature_insert_census';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_runtime_policy_runner_features_enforce
BEFORE INSERT OR UPDATE ON workflow_runtime_policy_runner_features
FOR EACH ROW EXECUTE FUNCTION automata_require_staging_workflow_runtime_runner_feature();

CREATE TRIGGER workflow_runtime_policy_runner_features_reject_delete
BEFORE DELETE ON workflow_runtime_policy_runner_features
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();

CREATE TRIGGER workflow_runtime_policy_runner_features_reject_truncate
BEFORE TRUNCATE ON workflow_runtime_policy_runner_features
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();

CREATE OR REPLACE FUNCTION automata_workflow_runtime_policy_canonical(text, uuid, bigint)
RETURNS bytea
LANGUAGE sql STABLE STRICT PARALLEL SAFE
AS $_$
WITH header AS (
    SELECT policy_schema, workspace_root, workspace_derivation_version,
           mapping_count, permission_policy_canonical, resource_policy_canonical
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = $3
), container_parts AS (
    SELECT mapping.selector, mapping.environment_profile_id,
           mapping.environment_profile_digest, mapping.operating_system,
           mapping.architecture, mapping.feature_count,
           mapping.runner_feature_schema, mapping.runner_feature_count,
           count(feature.feature)::integer AS actual_feature_count,
           COALESCE(
               string_agg(pg_catalog.to_json(feature.feature)::text, ',' ORDER BY feature.feature),
               ''
           ) AS encoded
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
             mapping.architecture, mapping.feature_count,
             mapping.runner_feature_schema, mapping.runner_feature_count
), runner_parts AS (
    SELECT mapping.selector,
           count(feature.feature)::integer AS actual_feature_count,
           (
               (
                   mapping.operating_system <> 'windows'
                   OR count(feature.feature) FILTER (
                       WHERE feature.feature IN (
                           'automata.core/default-posix-shell@v1',
                           'automata.core/javascript-actions@v1',
                           'automata.core/node12-actions@v1',
                           'automata.core/node16-actions@v1',
                           'automata.core/node20-actions@v1',
                           'automata.core/node24-actions@v1',
                           'automata.core/composite-actions@v1',
                           'automata.core/repository-actions@v1',
                           'automata.core/local-actions@v1'
                       )
                   ) = 0
               )
               AND (
                   mapping.operating_system NOT IN ('linux', 'macos')
                   OR count(feature.feature) FILTER (
                       WHERE feature.feature = 'automata.core/default-windows-shell@v1'
                   ) = 0
               )
               AND (
                   count(feature.feature) FILTER (
                       WHERE feature.feature IN (
                           'automata.core/node12-actions@v1',
                           'automata.core/node16-actions@v1',
                           'automata.core/node20-actions@v1',
                           'automata.core/node24-actions@v1'
                       )
                   ) = 0
                   OR count(feature.feature) FILTER (
                       WHERE feature.feature = 'automata.core/javascript-actions@v1'
                   ) = 1
               )
           ) AS profile_exact,
           COALESCE(
               string_agg(pg_catalog.to_json(feature.feature)::text, ',' ORDER BY feature.feature),
               ''
           ) AS encoded
    FROM workflow_runtime_policy_mappings AS mapping
    LEFT JOIN workflow_runtime_policy_runner_features AS feature
      ON feature.tenant_id = mapping.tenant_id
     AND feature.repository_id = mapping.repository_id
     AND feature.policy_revision = mapping.policy_revision
     AND feature.selector = mapping.selector
    WHERE mapping.tenant_id = $1
      AND mapping.repository_id = $2
      AND mapping.policy_revision = $3
    GROUP BY mapping.selector, mapping.operating_system
), mapping_parts AS (
    SELECT container.selector,
           '{"selector":' || pg_catalog.to_json(container.selector)::text
           || ',"environment_profile":{"id":'
           || pg_catalog.to_json(container.environment_profile_id)::text
           || ',"manifest_sha256":"'
           || pg_catalog.encode(container.environment_profile_digest, 'hex')
           || '"},"operating_system":'
           || pg_catalog.to_json(container.operating_system)::text
           || ',"architecture":'
           || pg_catalog.to_json(container.architecture)::text
           || CASE header.policy_schema
                WHEN 1 THEN ''
                WHEN 2 THEN ',"runner_features":{"schema":'
                    || container.runner_feature_schema::text
                    || ',"supported":[' || runner.encoded || ']}'
              END
           || ',"container_features":[' || container.encoded || ']}' AS encoded,
           container.actual_feature_count = container.feature_count AS container_exact,
           CASE header.policy_schema
             WHEN 1 THEN container.runner_feature_schema IS NULL
                 AND container.runner_feature_count = 0
                 AND runner.actual_feature_count = 0
                 AND runner.profile_exact
             WHEN 2 THEN container.runner_feature_schema = 1
                 AND runner.actual_feature_count = container.runner_feature_count
                 AND runner.profile_exact
             ELSE false
           END AS runner_exact
    FROM container_parts AS container
    JOIN runner_parts AS runner USING (selector)
    CROSS JOIN header
), catalog AS (
    SELECT count(*)::integer AS actual_mapping_count,
           bool_and(container_exact AND runner_exact) AS features_exact,
           COALESCE(string_agg(encoded, ',' ORDER BY selector), '') AS encoded
    FROM mapping_parts
)
SELECT pg_catalog.convert_to(
    '{"schema":' || header.policy_schema::text
    || ',"workspace":{"schema":1,"root":"/__w","derivation":1},"mappings":['
    || catalog.encoded || '],"permissions":'
    || pg_catalog.convert_from(header.permission_policy_canonical, 'UTF8')
    || ',"resources":'
    || pg_catalog.convert_from(header.resource_policy_canonical, 'UTF8')
    || '}',
    'UTF8'
)
FROM header CROSS JOIN catalog
WHERE header.policy_schema IN (1, 2)
  AND header.workspace_root = '/__w'
  AND header.workspace_derivation_version = 1
  AND automata_workflow_runtime_permission_policy_digest(
      header.permission_policy_canonical
  ) IS NOT NULL
  AND header.mapping_count = catalog.actual_mapping_count
  AND catalog.features_exact IS TRUE
$_$;

CREATE OR REPLACE FUNCTION automata_workflow_runtime_policy_digest(text, uuid, bigint)
RETURNS bytea
LANGUAGE sql STABLE STRICT PARALLEL SAFE
AS $_$
WITH header AS (
    SELECT policy_schema, workspace_root, workspace_derivation_version,
           mapping_count, permission_policy_canonical, resource_policy_canonical
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = $3
), container_parts AS (
    SELECT mapping.selector, mapping.environment_profile_id,
           mapping.environment_profile_digest, mapping.operating_system,
           mapping.architecture, mapping.feature_count,
           mapping.runner_feature_schema, mapping.runner_feature_count,
           count(feature.feature)::integer AS actual_feature_count,
           pg_catalog.int8send(count(feature.feature)::bigint)
           || COALESCE(
               string_agg(
                   automata_digest_part(pg_catalog.convert_to(feature.feature, 'UTF8')),
                   pg_catalog.decode('', 'hex') ORDER BY feature.feature
               ),
               pg_catalog.decode('', 'hex')
           ) AS encoded
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
             mapping.architecture, mapping.feature_count,
             mapping.runner_feature_schema, mapping.runner_feature_count
), runner_parts AS (
    SELECT mapping.selector,
           count(feature.feature)::integer AS actual_feature_count,
           (
               (
                   mapping.operating_system <> 'windows'
                   OR count(feature.feature) FILTER (
                       WHERE feature.feature IN (
                           'automata.core/default-posix-shell@v1',
                           'automata.core/javascript-actions@v1',
                           'automata.core/node12-actions@v1',
                           'automata.core/node16-actions@v1',
                           'automata.core/node20-actions@v1',
                           'automata.core/node24-actions@v1',
                           'automata.core/composite-actions@v1',
                           'automata.core/repository-actions@v1',
                           'automata.core/local-actions@v1'
                       )
                   ) = 0
               )
               AND (
                   mapping.operating_system NOT IN ('linux', 'macos')
                   OR count(feature.feature) FILTER (
                       WHERE feature.feature = 'automata.core/default-windows-shell@v1'
                   ) = 0
               )
               AND (
                   count(feature.feature) FILTER (
                       WHERE feature.feature IN (
                           'automata.core/node12-actions@v1',
                           'automata.core/node16-actions@v1',
                           'automata.core/node20-actions@v1',
                           'automata.core/node24-actions@v1'
                       )
                   ) = 0
                   OR count(feature.feature) FILTER (
                       WHERE feature.feature = 'automata.core/javascript-actions@v1'
                   ) = 1
               )
           ) AS profile_exact,
           pg_catalog.int8send(count(feature.feature)::bigint)
           || COALESCE(
               string_agg(
                   automata_digest_part(pg_catalog.convert_to(feature.feature, 'UTF8')),
                   pg_catalog.decode('', 'hex') ORDER BY feature.feature
               ),
               pg_catalog.decode('', 'hex')
           ) AS encoded
    FROM workflow_runtime_policy_mappings AS mapping
    LEFT JOIN workflow_runtime_policy_runner_features AS feature
      ON feature.tenant_id = mapping.tenant_id
     AND feature.repository_id = mapping.repository_id
     AND feature.policy_revision = mapping.policy_revision
     AND feature.selector = mapping.selector
    WHERE mapping.tenant_id = $1
      AND mapping.repository_id = $2
      AND mapping.policy_revision = $3
    GROUP BY mapping.selector, mapping.operating_system
), mapping_parts AS (
    SELECT container.selector,
           automata_digest_part(pg_catalog.convert_to(container.selector, 'UTF8'))
           || automata_digest_part(pg_catalog.convert_to(container.environment_profile_id, 'UTF8'))
           || container.environment_profile_digest
           || CASE container.operating_system
                WHEN 'linux' THEN pg_catalog.decode('01', 'hex')
                WHEN 'windows' THEN pg_catalog.decode('02', 'hex')
                WHEN 'macos' THEN pg_catalog.decode('03', 'hex')
              END
           || CASE container.architecture
                WHEN 'x86_64' THEN pg_catalog.decode('01', 'hex')
                WHEN 'aarch64' THEN pg_catalog.decode('02', 'hex')
              END
           || container.encoded
           || CASE header.policy_schema
                WHEN 1 THEN pg_catalog.decode('', 'hex')
                WHEN 2 THEN pg_catalog.convert_to('runner-features', 'UTF8')
                    || pg_catalog.decode('00', 'hex')
                    || pg_catalog.int2send(container.runner_feature_schema)
                    || runner.encoded
              END AS encoded,
           container.actual_feature_count = container.feature_count AS container_exact,
           CASE header.policy_schema
             WHEN 1 THEN container.runner_feature_schema IS NULL
                 AND container.runner_feature_count = 0
                 AND runner.actual_feature_count = 0
                 AND runner.profile_exact
             WHEN 2 THEN container.runner_feature_schema = 1
                 AND runner.actual_feature_count = container.runner_feature_count
                 AND runner.profile_exact
             ELSE false
           END AS runner_exact
    FROM container_parts AS container
    JOIN runner_parts AS runner USING (selector)
    CROSS JOIN header
), catalog AS (
    SELECT count(*)::integer AS actual_mapping_count,
           bool_and(container_exact AND runner_exact) AS features_exact,
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
    || automata_digest_part(pg_catalog.convert_to(header.workspace_root, 'UTF8'))
    || pg_catalog.int8send(header.mapping_count::bigint)
    || catalog.encoded
    || automata_workflow_runtime_permission_policy_digest(
        header.permission_policy_canonical
    )
    || automata_workflow_runtime_resource_policy_digest(
        header.resource_policy_canonical
    )
)
FROM header CROSS JOIN catalog
WHERE header.policy_schema IN (1, 2)
  AND automata_workflow_runtime_permission_policy_digest(
      header.permission_policy_canonical
  ) IS NOT NULL
  AND automata_workflow_runtime_resource_policy_digest(
      header.resource_policy_canonical
  ) IS NOT NULL
  AND header.mapping_count = catalog.actual_mapping_count
  AND catalog.features_exact IS TRUE
$_$;
