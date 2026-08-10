-- Current-only immutable workflow runtime policy and autonomous work queues.
--
-- Runtime policy is registered before admission and pinned by a database
-- trigger in the same transaction as every WorkflowPlan-v2 marker. Historical
-- catalog and workspace evidence is never reconstructed from current process
-- configuration. This migration deliberately refuses pre-contract logical
-- state instead of guessing a policy for it.

LOCK TABLE workflow_plan_v2_runs,
    github_provider_manifest_revisions,
    github_provider_manifest_current,
    github_provider_delivery_evidence,
    github_workflow_run_subject_evidence,
    workflow_plan_v2_jobs,
    workflow_plan_v2_activation_preparation_claims,
    workflow_plan_v2_activation_preparations,
    workflow_plan_v2_activation_publications,
    workflow_plan_v2_instances,
    workflow_plan_v2_materialization_claims,
    workflow_plan_v2_concrete_jobs
IN SHARE ROW EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM github_provider_manifest_revisions)
        OR EXISTS (SELECT 1 FROM github_provider_manifest_current)
        OR EXISTS (SELECT 1 FROM github_provider_delivery_evidence)
        OR EXISTS (SELECT 1 FROM github_workflow_run_subject_evidence)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_runs)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_jobs)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_activation_preparation_claims)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_activation_preparations)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_activation_publications)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_instances)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_materialization_claims)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_concrete_jobs)
    THEN
        RAISE EXCEPTION 'pre-policy WorkflowPlan-v2 state must be explicitly drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_current_only';
    END IF;
END;
$automata$;

CREATE TABLE workflow_runtime_policy_revisions (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    policy_revision BIGINT NOT NULL,
    policy_digest BYTEA NOT NULL,
    canonical_policy BYTEA NOT NULL,
    policy_schema SMALLINT NOT NULL,
    workspace_root TEXT COLLATE "C" NOT NULL,
    workspace_derivation_version SMALLINT NOT NULL,
    mapping_count INTEGER NOT NULL,
    state TEXT NOT NULL,
    registered_at_ms BIGINT NOT NULL,
    sealed_at_ms BIGINT,
    CONSTRAINT workflow_runtime_policy_revisions_pk
        PRIMARY KEY (tenant_id, repository_id, policy_revision),
    CONSTRAINT workflow_runtime_policy_revisions_exact_unique
        UNIQUE (tenant_id, repository_id, policy_revision, policy_digest),
    CONSTRAINT workflow_runtime_policy_revisions_repository_fk
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_runtime_policy_revisions_identity CHECK (
        repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND policy_revision > 0
        AND octet_length(policy_digest) = 32
        AND policy_schema = 1
    ),
    CONSTRAINT workflow_runtime_policy_revisions_workspace CHECK (
        workspace_derivation_version = 1
        AND workspace_root = '/__w'
    ),
    CONSTRAINT workflow_runtime_policy_revisions_canonical_size CHECK (
        octet_length(canonical_policy) BETWEEN 1 AND 65536
    ),
    CONSTRAINT workflow_runtime_policy_revisions_mapping_count CHECK (
        mapping_count BETWEEN 1 AND 64
    ),
    CONSTRAINT workflow_runtime_policy_revisions_lifecycle CHECK ((
        (state = 'staging' AND sealed_at_ms IS NULL)
        OR (state = 'sealed' AND sealed_at_ms = registered_at_ms)
    ) IS TRUE),
    CONSTRAINT workflow_runtime_policy_revisions_time CHECK (
        registered_at_ms >= 0
    )
);

CREATE TABLE workflow_runtime_policy_mappings (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    policy_revision BIGINT NOT NULL,
    selector TEXT COLLATE "C" NOT NULL,
    environment_profile_id TEXT COLLATE "C" NOT NULL,
    environment_profile_digest BYTEA NOT NULL,
    operating_system TEXT NOT NULL,
    architecture TEXT NOT NULL,
    feature_count INTEGER NOT NULL,
    CONSTRAINT workflow_runtime_policy_mappings_pk
        PRIMARY KEY (tenant_id, repository_id, policy_revision, selector),
    CONSTRAINT workflow_runtime_policy_mappings_revision_fk
        FOREIGN KEY (tenant_id, repository_id, policy_revision)
        REFERENCES workflow_runtime_policy_revisions(
            tenant_id, repository_id, policy_revision
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_runtime_policy_mappings_selector CHECK (
        char_length(selector) BETWEEN 1 AND 256
        AND selector = lower(selector)
        AND btrim(selector) = selector
        AND selector ~ '^[ -~]+$'
    ),
    CONSTRAINT workflow_runtime_policy_mappings_environment CHECK (
        octet_length(environment_profile_id) BETWEEN 3 AND 128
        AND environment_profile_id ~ '^[a-z]([a-z0-9-]*[a-z0-9])?(\.[a-z]([a-z0-9-]*[a-z0-9])?)*/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'
        AND octet_length(environment_profile_digest) = 32
    ),
    CONSTRAINT workflow_runtime_policy_mappings_platform CHECK (
        operating_system IN ('linux', 'windows', 'macos')
        AND architecture IN ('x86_64', 'aarch64')
    ),
    CONSTRAINT workflow_runtime_policy_mappings_feature_count CHECK (
        feature_count BETWEEN 0 AND 64
    )
);

CREATE TABLE workflow_runtime_policy_features (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    policy_revision BIGINT NOT NULL,
    selector TEXT COLLATE "C" NOT NULL,
    feature TEXT COLLATE "C" NOT NULL,
    CONSTRAINT workflow_runtime_policy_features_pk PRIMARY KEY (
        tenant_id, repository_id, policy_revision, selector, feature
    ),
    CONSTRAINT workflow_runtime_policy_features_mapping_fk FOREIGN KEY (
        tenant_id, repository_id, policy_revision, selector
    ) REFERENCES workflow_runtime_policy_mappings(
        tenant_id, repository_id, policy_revision, selector
    ) ON DELETE RESTRICT,
    CONSTRAINT workflow_runtime_policy_features_shape CHECK (
        octet_length(feature) BETWEEN 1 AND 128
        AND CASE
          WHEN feature ~ '^[a-z]([a-z0-9-]*[a-z0-9])?(\.[a-z]([a-z0-9-]*[a-z0-9])?)*/[a-z]([a-z0-9-]*[a-z0-9])?@v[1-9][0-9]{0,4}$'
          THEN substring(feature FROM '@v([1-9][0-9]{0,4})$')::INTEGER BETWEEN 1 AND 65535
          ELSE FALSE
        END
    )
);

CREATE FUNCTION automata_workflow_runtime_policy_digest_part(BYTEA)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.int8send(pg_catalog.octet_length($1)::BIGINT) || $1
$automata$;

CREATE FUNCTION automata_workflow_runtime_policy_digest(TEXT, UUID, BIGINT)
RETURNS BYTEA
LANGUAGE SQL
STABLE
STRICT
PARALLEL SAFE
AS $automata$
WITH header AS (
    SELECT policy_schema, workspace_root, workspace_derivation_version,
           mapping_count
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
)
FROM header CROSS JOIN catalog
WHERE header.mapping_count = catalog.actual_mapping_count
  AND catalog.features_exact IS TRUE
$automata$;

CREATE FUNCTION automata_workflow_runtime_policy_canonical(TEXT, UUID, BIGINT)
RETURNS BYTEA
LANGUAGE SQL
STABLE
STRICT
PARALLEL SAFE
AS $automata$
WITH header AS (
    SELECT policy_schema, workspace_root, workspace_derivation_version,
           mapping_count
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
    || catalog.encoded || ']}',
    'UTF8'
)
FROM header CROSS JOIN catalog
WHERE header.policy_schema = 1
  AND header.workspace_root = '/__w'
  AND header.workspace_derivation_version = 1
  AND header.mapping_count = catalog.actual_mapping_count
  AND catalog.features_exact IS TRUE
$automata$;

CREATE FUNCTION automata_enforce_workflow_runtime_policy_revision()
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

CREATE TRIGGER workflow_runtime_policy_revisions_enforce
BEFORE INSERT OR UPDATE ON workflow_runtime_policy_revisions
FOR EACH ROW EXECUTE FUNCTION automata_enforce_workflow_runtime_policy_revision();

-- A direct writer must not be able to commit an incomplete staging catalog and
-- permanently squat the next sequential revision. Registration may use staging
-- only inside its transaction; every deferred observation must resolve to the
-- exact sealed row before commit.
CREATE FUNCTION automata_require_sealed_workflow_runtime_policy_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    durable_state TEXT;
    selected_current BOOLEAN := FALSE;
BEGIN
    SELECT state INTO durable_state
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND policy_revision = NEW.policy_revision;
    SELECT EXISTS (
        SELECT 1
        FROM workflow_runtime_policy_current AS current_policy
        WHERE current_policy.tenant_id = NEW.tenant_id
          AND current_policy.repository_id = NEW.repository_id
          AND current_policy.policy_revision = NEW.policy_revision
          AND current_policy.policy_digest = NEW.policy_digest
    ) INTO selected_current;
    IF durable_state IS DISTINCT FROM 'sealed' OR selected_current IS NOT TRUE THEN
        RAISE EXCEPTION 'workflow runtime policy revision must seal and become current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_revision_must_be_current';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_runtime_policy_revision_must_seal
AFTER INSERT OR UPDATE ON workflow_runtime_policy_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_sealed_workflow_runtime_policy_revision();

CREATE FUNCTION automata_require_staging_workflow_runtime_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    parent_state TEXT;
    declared_count INTEGER;
    inserted_count INTEGER;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'workflow runtime policy catalog rows are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_catalog_immutable';
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
    IF TG_TABLE_NAME = 'workflow_runtime_policy_mappings' THEN
        SELECT mapping_count INTO declared_count
        FROM workflow_runtime_policy_revisions
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND policy_revision = NEW.policy_revision;
        SELECT count(*)::INTEGER INTO inserted_count
        FROM workflow_runtime_policy_mappings
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND policy_revision = NEW.policy_revision;
        IF inserted_count >= declared_count OR inserted_count >= 64 THEN
            RAISE EXCEPTION 'workflow runtime policy mapping census exceeded'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_runtime_policy_mapping_insert_census';
        END IF;
    ELSE
        SELECT feature_count INTO declared_count
        FROM workflow_runtime_policy_mappings
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND policy_revision = NEW.policy_revision
          AND selector = NEW.selector
        FOR UPDATE;
        SELECT count(*)::INTEGER INTO inserted_count
        FROM workflow_runtime_policy_features
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND policy_revision = NEW.policy_revision
          AND selector = NEW.selector;
        IF declared_count IS NULL
            OR inserted_count >= declared_count
            OR inserted_count >= 64
        THEN
            RAISE EXCEPTION 'workflow runtime policy feature census exceeded'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_runtime_policy_feature_insert_census';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runtime_policy_mappings_enforce
BEFORE INSERT OR UPDATE ON workflow_runtime_policy_mappings
FOR EACH ROW EXECUTE FUNCTION automata_require_staging_workflow_runtime_policy();
CREATE TRIGGER workflow_runtime_policy_features_enforce
BEFORE INSERT OR UPDATE ON workflow_runtime_policy_features
FOR EACH ROW EXECUTE FUNCTION automata_require_staging_workflow_runtime_policy();

CREATE TABLE workflow_runtime_policy_current (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    policy_revision BIGINT NOT NULL,
    policy_digest BYTEA NOT NULL,
    activated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_runtime_policy_current_pk PRIMARY KEY (
        tenant_id, repository_id
    ),
    CONSTRAINT workflow_runtime_policy_current_revision_fk FOREIGN KEY (
        tenant_id, repository_id, policy_revision
    ) REFERENCES workflow_runtime_policy_revisions(
        tenant_id, repository_id, policy_revision
    ) ON DELETE RESTRICT,
    CONSTRAINT workflow_runtime_policy_current_shape CHECK (
        policy_revision > 0
        AND octet_length(policy_digest) = 32
        AND activated_at_ms >= 0
    )
);

CREATE FUNCTION automata_enforce_workflow_runtime_policy_current()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    revision workflow_runtime_policy_revisions%ROWTYPE;
BEGIN
    SELECT * INTO revision
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND policy_revision = NEW.policy_revision
    FOR SHARE;
    IF revision.state IS DISTINCT FROM 'sealed'
        OR revision.policy_digest IS DISTINCT FROM NEW.policy_digest
        OR NEW.activated_at_ms IS DISTINCT FROM revision.sealed_at_ms
    THEN
        RAISE EXCEPTION 'current workflow runtime policy lacks exact sealed evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_current_exact';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.policy_revision <> 1 THEN
            RAISE EXCEPTION 'initial workflow runtime policy revision must be one'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_runtime_policy_current_initial';
        END IF;
    ELSIF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR OLD.policy_revision = 9223372036854775807
        OR NEW.policy_revision <> OLD.policy_revision + 1
        OR NEW.policy_digest IS NOT DISTINCT FROM OLD.policy_digest
        OR NEW.activated_at_ms < OLD.activated_at_ms
    THEN
        RAISE EXCEPTION 'workflow runtime policy current transition is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_current_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runtime_policy_current_enforce
BEFORE INSERT OR UPDATE ON workflow_runtime_policy_current
FOR EACH ROW EXECUTE FUNCTION automata_enforce_workflow_runtime_policy_current();

ALTER TABLE github_provider_manifest_revisions
    DROP CONSTRAINT github_provider_manifest_revisions_digest_canonical,
    ADD COLUMN runner_policy_digest BYTEA NOT NULL,
    ADD COLUMN runner_policy_object_key TEXT COLLATE "C" NOT NULL,
    ADD COLUMN runner_policy_size_bytes BIGINT NOT NULL,
    ADD COLUMN runner_policy_media_type TEXT COLLATE "C" NOT NULL,
    ADD COLUMN runtime_policy_revision BIGINT NOT NULL,
    ADD COLUMN runtime_policy_digest BYTEA NOT NULL,
    ADD CONSTRAINT github_provider_manifest_revisions_runner_policy_shape CHECK (
        octet_length(runner_policy_digest) = 32
        AND octet_length(runner_policy_object_key) BETWEEN 1 AND 1024
        AND btrim(runner_policy_object_key) = runner_policy_object_key
        AND runner_policy_object_key !~ '[[:cntrl:]]'
        AND runner_policy_object_key = 'github/runner-policy/v1/'
            || pg_catalog.encode(runner_policy_digest, 'hex') || '.json'
        AND runner_policy_size_bytes BETWEEN 1 AND 65536
        AND runner_policy_media_type =
            'application/vnd.automata.github-runner-policy+json'
    ),
    ADD CONSTRAINT github_provider_manifest_revisions_runtime_policy_shape CHECK (
        runtime_policy_revision > 0
        AND octet_length(runtime_policy_digest) = 32
    ),
    ADD CONSTRAINT github_provider_manifest_revisions_runtime_policy_fk FOREIGN KEY (
        tenant_id, repository_id, runtime_policy_revision, runtime_policy_digest
    ) REFERENCES workflow_runtime_policy_revisions(
        tenant_id, repository_id, policy_revision, policy_digest
    ) ON DELETE RESTRICT;

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
    pg_catalog.convert_to('automata.store.github-provider-manifest.v3', 'UTF8')
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

CREATE FUNCTION automata_require_github_manifest_runtime_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    policy workflow_runtime_policy_revisions%ROWTYPE;
BEGIN
    SELECT revision.* INTO policy
    FROM workflow_runtime_policy_current AS current_policy
    JOIN workflow_runtime_policy_revisions AS revision
      ON revision.tenant_id = current_policy.tenant_id
     AND revision.repository_id = current_policy.repository_id
     AND revision.policy_revision = current_policy.policy_revision
     AND revision.policy_digest = current_policy.policy_digest
    WHERE current_policy.tenant_id = NEW.tenant_id
      AND current_policy.repository_id = NEW.repository_id
      AND current_policy.policy_revision = NEW.runtime_policy_revision
      AND current_policy.policy_digest = NEW.runtime_policy_digest
    FOR SHARE OF current_policy, revision;
    IF policy.state IS DISTINCT FROM 'sealed'
        OR pg_catalog.sha256(policy.canonical_policy) IS DISTINCT FROM
            NEW.runner_policy_digest
        OR pg_catalog.octet_length(policy.canonical_policy) IS DISTINCT FROM
            NEW.runner_policy_size_bytes
    THEN
        RAISE EXCEPTION 'GitHub manifest runtime policy is not exact sealed evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_runtime_policy_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_provider_manifest_revisions_01_runtime_policy
BEFORE INSERT ON github_provider_manifest_revisions
FOR EACH ROW EXECUTE FUNCTION automata_require_github_manifest_runtime_policy();

CREATE OR REPLACE FUNCTION automata_github_provider_manifest_current_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
$automata$;

-- Policy currentness and provider-manifest currentness are one repository
-- authority transition. Either row may be written first inside the composite
-- transaction, but no transaction may expose only one half or a stale pair.
CREATE FUNCTION automata_require_current_manifest_runtime_policy_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    pair_exists BOOLEAN;
    durable_tenant TEXT;
    durable_repository UUID;
BEGIN
    durable_tenant := NEW.tenant_id;
    durable_repository := NEW.repository_id;
    SELECT EXISTS (
        SELECT 1
        FROM workflow_runtime_policy_current AS current_policy
        JOIN github_provider_manifest_current AS current_manifest
          ON current_manifest.tenant_id = current_policy.tenant_id
         AND current_manifest.repository_id = current_policy.repository_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = current_manifest.tenant_id
         AND manifest.repository_id = current_manifest.repository_id
         AND manifest.provider_connection_id = current_manifest.provider_connection_id
         AND manifest.manifest_revision = current_manifest.manifest_revision
         AND manifest.manifest_digest = current_manifest.manifest_digest
        WHERE current_policy.tenant_id = durable_tenant
          AND current_policy.repository_id = durable_repository
          AND manifest.runtime_policy_revision = current_policy.policy_revision
          AND manifest.runtime_policy_digest = current_policy.policy_digest
    ) INTO pair_exists;
    IF pair_exists IS NOT TRUE THEN
        RAISE EXCEPTION 'current provider manifest and runtime policy are not an exact pair'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_current_runtime_policy_pair';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_runtime_policy_current_requires_manifest
AFTER INSERT OR UPDATE ON workflow_runtime_policy_current
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_current_manifest_runtime_policy_pair();

CREATE CONSTRAINT TRIGGER github_provider_manifest_current_requires_runtime_policy
AFTER INSERT OR UPDATE ON github_provider_manifest_current
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_current_manifest_runtime_policy_pair();

CREATE FUNCTION automata_require_inserted_manifest_revision_current()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM github_provider_manifest_current AS current_manifest
        WHERE current_manifest.tenant_id = NEW.tenant_id
          AND current_manifest.repository_id = NEW.repository_id
          AND current_manifest.provider_connection_id = NEW.provider_connection_id
          AND current_manifest.manifest_revision = NEW.manifest_revision
          AND current_manifest.manifest_digest = NEW.manifest_digest
    ) THEN
        RAISE EXCEPTION 'inserted provider manifest revision must become current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_revision_must_be_current';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER github_provider_manifest_revision_must_be_current
AFTER INSERT ON github_provider_manifest_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_inserted_manifest_revision_current();

CREATE TABLE workflow_plan_v2_runtime_policy_pins (
    run_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    policy_revision BIGINT NOT NULL,
    policy_digest BYTEA NOT NULL,
    pinned_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_runtime_policy_pins_run_fk
        FOREIGN KEY (run_id) REFERENCES workflow_plan_v2_runs(run_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT workflow_plan_v2_runtime_policy_pins_revision_fk FOREIGN KEY (
        tenant_id, repository_id, policy_revision, policy_digest
    ) REFERENCES workflow_runtime_policy_revisions(
        tenant_id, repository_id, policy_revision, policy_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_runtime_policy_pins_repository_fk FOREIGN KEY (
        tenant_id, repository_id
    ) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_runtime_policy_pins_shape CHECK (
        run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND policy_revision > 0
        AND octet_length(policy_digest) = 32
        AND pinned_at_ms >= 0
    )
);

CREATE FUNCTION automata_require_workflow_runtime_policy_pin_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM github_workflow_run_subject_evidence AS subject
    JOIN github_provider_delivery_evidence AS delivery
      ON delivery.provider_delivery_id = subject.provider_delivery_id
     AND delivery.tenant_id = subject.tenant_id
     AND delivery.repository_id = subject.repository_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = delivery.tenant_id
     AND manifest.repository_id = delivery.repository_id
     AND manifest.provider_connection_id = delivery.provider_connection_id
     AND manifest.manifest_revision = delivery.provider_manifest_revision
     AND manifest.manifest_digest = delivery.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = manifest.tenant_id
     AND policy.repository_id = manifest.repository_id
     AND policy.policy_revision = manifest.runtime_policy_revision
     AND policy.policy_digest = manifest.runtime_policy_digest
     AND policy.state = 'sealed'
    JOIN workflow_runs AS run
      ON run.id = subject.run_id
     AND run.repository_id = subject.repository_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = subject.run_id
    WHERE subject.run_id = NEW.run_id
      AND subject.tenant_id = NEW.tenant_id
      AND subject.repository_id = NEW.repository_id
      AND subject.admitted_at_ms = NEW.pinned_at_ms
      AND manifest.runtime_policy_revision = NEW.policy_revision
      AND manifest.runtime_policy_digest = NEW.policy_digest
    FOR SHARE OF subject, delivery, manifest, policy, run, marker;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow runtime policy pin lacks authenticated manifest provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_runtime_policy_pin_provenance';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_runtime_policy_pins_00_provenance
BEFORE INSERT ON workflow_plan_v2_runtime_policy_pins
FOR EACH ROW EXECUTE FUNCTION automata_require_workflow_runtime_policy_pin_provenance();

CREATE FUNCTION automata_pin_github_workflow_runtime_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    rows_inserted BIGINT;
BEGIN
    INSERT INTO workflow_plan_v2_runtime_policy_pins (
        run_id, tenant_id, repository_id, policy_revision,
        policy_digest, pinned_at_ms
    )
    SELECT NEW.run_id, NEW.tenant_id, NEW.repository_id,
           manifest.runtime_policy_revision, manifest.runtime_policy_digest,
           NEW.admitted_at_ms
    FROM github_provider_delivery_evidence AS delivery
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = delivery.tenant_id
     AND manifest.repository_id = delivery.repository_id
     AND manifest.provider_connection_id = delivery.provider_connection_id
     AND manifest.manifest_revision = delivery.provider_manifest_revision
     AND manifest.manifest_digest = delivery.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = manifest.tenant_id
     AND policy.repository_id = manifest.repository_id
     AND policy.policy_revision = manifest.runtime_policy_revision
     AND policy.policy_digest = manifest.runtime_policy_digest
     AND policy.state = 'sealed'
    WHERE delivery.provider_delivery_id = NEW.provider_delivery_id
      AND delivery.tenant_id = NEW.tenant_id
      AND delivery.repository_id = NEW.repository_id;
    GET DIAGNOSTICS rows_inserted = ROW_COUNT;
    IF rows_inserted <> 1 THEN
        RAISE EXCEPTION 'GitHub WorkflowPlan-v2 run lacks its historical manifest runtime policy'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_runtime_policy_pin_required';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_workflow_run_subject_evidence_10_pin_runtime_policy
AFTER INSERT ON github_workflow_run_subject_evidence
FOR EACH ROW EXECUTE FUNCTION automata_pin_github_workflow_runtime_policy();

ALTER TABLE workflow_plan_v2_runs
    ADD COLUMN admission_graph_sealed_at_ms BIGINT,
    ADD CONSTRAINT workflow_plan_v2_runs_admission_graph_seal_time CHECK (
        admission_graph_sealed_at_ms IS NULL OR admission_graph_sealed_at_ms >= admitted_at_ms
    );

CREATE FUNCTION automata_enforce_workflow_admission_graph_seal()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.admission_graph_sealed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'workflow admission graph must begin unsealed'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_admission_graph_construction_window';
        END IF;
        RETURN NEW;
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF OLD.admission_graph_sealed_at_ms IS NOT NULL THEN
        IF NEW.admission_graph_sealed_at_ms IS DISTINCT FROM
           OLD.admission_graph_sealed_at_ms
        THEN
            RAISE EXCEPTION 'workflow admission graph seal is immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_admission_graph_seal_immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.admission_graph_sealed_at_ms IS NULL
        OR NEW.admission_graph_sealed_at_ms <> NEW.updated_at_ms
        OR NEW.admission_graph_sealed_at_ms > database_now
        OR database_now - NEW.admission_graph_sealed_at_ms > 60000
    THEN
        RAISE EXCEPTION 'workflow admission graph seal transition is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_admission_graph_seal_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_runs_00_admission_graph_seal
BEFORE INSERT OR UPDATE ON workflow_plan_v2_runs
FOR EACH ROW EXECUTE FUNCTION automata_enforce_workflow_admission_graph_seal();

CREATE FUNCTION automata_require_open_workflow_admission_graph()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN github_workflow_run_subject_evidence AS subject ON subject.run_id = marker.run_id
    JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND subject.admitted_at_ms = receipt.committed_at_ms
      AND pin.pinned_at_ms = subject.admitted_at_ms
    FOR KEY SHARE OF marker, receipt, subject, pin;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow graph insertion is outside authenticated admission'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_admission_graph_construction_window';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_01_admission_graph_open
BEFORE INSERT ON workflow_plan_v2_jobs
FOR EACH ROW EXECUTE FUNCTION automata_require_open_workflow_admission_graph();
CREATE TRIGGER workflow_plan_v2_dependencies_01_admission_graph_open
BEFORE INSERT ON workflow_plan_v2_dependencies
FOR EACH ROW EXECUTE FUNCTION automata_require_open_workflow_admission_graph();

CREATE FUNCTION automata_require_workflow_runtime_policy_pin()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runtime_policy_pins AS pin
        WHERE pin.run_id = NEW.run_id
    ) OR EXISTS (
        SELECT 1 FROM workflow_plan_v2_runs AS marker
        WHERE marker.run_id = NEW.run_id
          AND marker.admission_graph_sealed_at_ms IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM workflow_plan_v2_jobs AS job WHERE job.run_id = NEW.run_id
    ) OR EXISTS (
        SELECT 1
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = job.run_id
        WHERE job.run_id = NEW.run_id
          AND (job.runtime_policy_revision, job.runtime_policy_digest)
              IS DISTINCT FROM (pin.policy_revision, pin.policy_digest)
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 admission requires authenticated provider runtime policy'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_runtime_policy_pin_required';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_runs_require_runtime_policy_pin
AFTER INSERT ON workflow_plan_v2_runs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_workflow_runtime_policy_pin();

CREATE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'retained workflow runtime policy evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'workflow_runtime_policy_retained_immutable';
END;
$automata$;

CREATE TRIGGER workflow_runtime_policy_revisions_reject_delete
BEFORE DELETE ON workflow_runtime_policy_revisions FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_runtime_policy_revisions_reject_truncate
BEFORE TRUNCATE ON workflow_runtime_policy_revisions FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_runtime_policy_mappings_reject_delete
BEFORE DELETE ON workflow_runtime_policy_mappings FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_runtime_policy_mappings_reject_truncate
BEFORE TRUNCATE ON workflow_runtime_policy_mappings FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_runtime_policy_features_reject_delete
BEFORE DELETE ON workflow_runtime_policy_features FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_runtime_policy_features_reject_truncate
BEFORE TRUNCATE ON workflow_runtime_policy_features FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_runtime_policy_current_reject_delete
BEFORE DELETE ON workflow_runtime_policy_current FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_runtime_policy_current_reject_truncate
BEFORE TRUNCATE ON workflow_runtime_policy_current FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_plan_v2_runtime_policy_pins_reject_update
BEFORE UPDATE ON workflow_plan_v2_runtime_policy_pins FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_plan_v2_runtime_policy_pins_reject_delete
BEFORE DELETE ON workflow_plan_v2_runtime_policy_pins FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();
CREATE TRIGGER workflow_plan_v2_runtime_policy_pins_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_runtime_policy_pins FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation();

-- Pin propagation is current-only. Every downstream row carries the exact
-- run pin, independently of the authority profile and repository visibility.
ALTER TABLE workflow_plan_v2_jobs
    ADD COLUMN runtime_policy_revision BIGINT NOT NULL,
    ADD COLUMN runtime_policy_digest BYTEA NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_jobs_runtime_policy CHECK (
        runtime_policy_revision > 0 AND octet_length(runtime_policy_digest) = 32
    );
ALTER TABLE workflow_plan_v2_activation_preparation_claims
    ADD COLUMN runtime_policy_revision BIGINT NOT NULL,
    ADD COLUMN runtime_policy_digest BYTEA NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_preparation_claims_runtime_policy CHECK (
        runtime_policy_revision > 0 AND octet_length(runtime_policy_digest) = 32
    );
ALTER TABLE workflow_plan_v2_activation_preparations
    ADD COLUMN runtime_policy_revision BIGINT NOT NULL,
    ADD COLUMN runtime_policy_digest BYTEA NOT NULL,
    ADD COLUMN claim_origin_selection_id UUID NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_preparations_runtime_policy CHECK (
        runtime_policy_revision > 0 AND octet_length(runtime_policy_digest) = 32
    ),
    ADD CONSTRAINT workflow_plan_v2_preparations_selection_origin CHECK (
        claim_origin_selection_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
    );
ALTER TABLE workflow_plan_v2_activation_publications
    ADD COLUMN runtime_policy_revision BIGINT NOT NULL,
    ADD COLUMN runtime_policy_digest BYTEA NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_publications_runtime_policy CHECK (
        runtime_policy_revision > 0 AND octet_length(runtime_policy_digest) = 32
    );
ALTER TABLE workflow_plan_v2_instances
    ADD COLUMN runtime_policy_revision BIGINT NOT NULL,
    ADD COLUMN runtime_policy_digest BYTEA NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_instances_runtime_policy CHECK (
        runtime_policy_revision > 0 AND octet_length(runtime_policy_digest) = 32
    );
ALTER TABLE workflow_plan_v2_materialization_claims
    ADD COLUMN runtime_policy_revision BIGINT NOT NULL,
    ADD COLUMN runtime_policy_digest BYTEA NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_materialization_claims_runtime_policy CHECK (
        runtime_policy_revision > 0 AND octet_length(runtime_policy_digest) = 32
    );
ALTER TABLE workflow_plan_v2_concrete_jobs
    ADD COLUMN runtime_policy_revision BIGINT NOT NULL,
    ADD COLUMN runtime_policy_digest BYTEA NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_concrete_jobs_runtime_policy CHECK (
        runtime_policy_revision > 0 AND octet_length(runtime_policy_digest) = 32
    );

CREATE FUNCTION automata_validate_workflow_runtime_policy_propagation()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    expected_revision BIGINT;
    expected_digest BYTEA;
    upstream_exact BOOLEAN := FALSE;
BEGIN
    SELECT policy_revision, policy_digest
      INTO expected_revision, expected_digest
    FROM workflow_plan_v2_runtime_policy_pins AS pin
    WHERE run_id = NEW.run_id
    FOR KEY SHARE OF pin;
    IF NOT FOUND
        OR NEW.runtime_policy_revision IS DISTINCT FROM expected_revision
        OR NEW.runtime_policy_digest IS DISTINCT FROM expected_digest
    THEN
        RAISE EXCEPTION 'logical workflow row lacks its exact runtime policy pin'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_propagation_exact';
    END IF;

    -- The run pin is necessary but not sufficient: lock and compare the exact
    -- immediate historical chain so no direct SQL writer can splice two rows
    -- which happen to name the same run. No current pointer participates.
    IF TG_TABLE_NAME = 'workflow_plan_v2_activation_preparation_claims' THEN
        SELECT (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM workflow_plan_v2_jobs AS job
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
        FOR KEY SHARE OF job;
    ELSIF TG_TABLE_NAME = 'workflow_plan_v2_activation_preparations' THEN
        SELECT (claim.runtime_policy_revision, claim.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM workflow_plan_v2_activation_preparation_claims AS claim
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = claim.run_id
         AND job.invocation_id = claim.invocation_id
         AND job.id = claim.logical_job_id
        WHERE claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF claim, job;
    ELSIF TG_TABLE_NAME = 'workflow_plan_v2_activation_publications' THEN
        SELECT (preparation.runtime_policy_revision,
                preparation.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM workflow_plan_v2_activation_preparations AS preparation
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = preparation.run_id
         AND job.invocation_id = preparation.invocation_id
         AND job.id = preparation.logical_job_id
        WHERE preparation.run_id = NEW.run_id
          AND preparation.invocation_id = NEW.invocation_id
          AND preparation.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF preparation, job;
    ELSIF TG_TABLE_NAME = 'workflow_plan_v2_instances' THEN
        SELECT (publication.runtime_policy_revision,
                publication.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM workflow_plan_v2_activation_publications AS publication
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = publication.run_id
         AND job.invocation_id = publication.invocation_id
         AND job.id = publication.logical_job_id
        WHERE publication.run_id = NEW.run_id
          AND publication.invocation_id = NEW.invocation_id
          AND publication.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF publication, job;
    ELSIF TG_TABLE_NAME = 'workflow_plan_v2_materialization_claims' THEN
        SELECT (instance.runtime_policy_revision, instance.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (publication.runtime_policy_revision,
                    publication.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM workflow_plan_v2_instances AS instance
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = instance.run_id
         AND job.invocation_id = instance.invocation_id
         AND job.id = instance.logical_job_id
        WHERE instance.id = NEW.instance_id
          AND instance.run_id = NEW.run_id
          AND instance.invocation_id = NEW.invocation_id
          AND instance.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF instance, publication, job;
    ELSIF TG_TABLE_NAME = 'workflow_plan_v2_concrete_jobs' THEN
        SELECT (claim.runtime_policy_revision, claim.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (instance.runtime_policy_revision, instance.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (publication.runtime_policy_revision,
                    publication.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
               AND (job.runtime_policy_revision, job.runtime_policy_digest)
                   IS NOT DISTINCT FROM (expected_revision, expected_digest)
          INTO upstream_exact
        FROM workflow_plan_v2_materialization_claims AS claim
        JOIN workflow_plan_v2_instances AS instance
          ON instance.id = claim.instance_id
         AND instance.run_id = claim.run_id
         AND instance.invocation_id = claim.invocation_id
         AND instance.logical_job_id = claim.logical_job_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = instance.run_id
         AND job.invocation_id = instance.invocation_id
         AND job.id = instance.logical_job_id
        WHERE claim.instance_id = NEW.instance_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
        FOR KEY SHARE OF claim, instance, publication, job;
    ELSE
        RAISE EXCEPTION 'runtime policy propagation trigger is attached to an unknown table'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_propagation_table';
    END IF;

    IF upstream_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'logical workflow runtime policy differs from its locked upstream chain'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_upstream_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_preparation_claims_00_runtime_policy
BEFORE INSERT ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_runtime_policy_propagation();
CREATE TRIGGER workflow_plan_v2_preparations_00_runtime_policy
BEFORE INSERT ON workflow_plan_v2_activation_preparations
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_runtime_policy_propagation();
CREATE TRIGGER workflow_plan_v2_publications_00_runtime_policy
BEFORE INSERT ON workflow_plan_v2_activation_publications
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_runtime_policy_propagation();
CREATE TRIGGER workflow_plan_v2_instances_00_runtime_policy
BEFORE INSERT ON workflow_plan_v2_instances
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_runtime_policy_propagation();
CREATE TRIGGER workflow_plan_v2_materialization_claims_00_runtime_policy
BEFORE INSERT ON workflow_plan_v2_materialization_claims
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_runtime_policy_propagation();
CREATE TRIGGER workflow_plan_v2_concrete_jobs_00_runtime_policy
BEFORE INSERT ON workflow_plan_v2_concrete_jobs
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_runtime_policy_propagation();

CREATE FUNCTION automata_enforce_logical_job_runtime_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    expected_revision BIGINT;
    expected_digest BYTEA;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT policy_revision, policy_digest
          INTO expected_revision, expected_digest
        FROM workflow_plan_v2_runtime_policy_pins AS pin
        WHERE run_id = NEW.run_id
        FOR KEY SHARE OF pin;
        IF NOT FOUND
            OR NEW.runtime_policy_revision IS DISTINCT FROM expected_revision
            OR NEW.runtime_policy_digest IS DISTINCT FROM expected_digest
        THEN
            RAISE EXCEPTION 'inserted logical job runtime policy lacks its run pin'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_plan_v2_jobs_runtime_policy_binding';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.runtime_policy_revision IS DISTINCT FROM OLD.runtime_policy_revision
        OR NEW.runtime_policy_digest IS DISTINCT FROM OLD.runtime_policy_digest
    THEN
        RAISE EXCEPTION 'logical job runtime policy is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_jobs_runtime_policy_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_enforce_runtime_policy
BEFORE INSERT OR UPDATE ON workflow_plan_v2_jobs
FOR EACH ROW EXECUTE FUNCTION automata_enforce_logical_job_runtime_policy();

CREATE FUNCTION automata_enforce_runtime_policy_columns_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.runtime_policy_revision IS DISTINCT FROM OLD.runtime_policy_revision
        OR NEW.runtime_policy_digest IS DISTINCT FROM OLD.runtime_policy_digest
    THEN
        RAISE EXCEPTION 'logical runtime policy evidence is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_downstream_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_preparation_claims_policy_immutable
BEFORE UPDATE ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW EXECUTE FUNCTION automata_enforce_runtime_policy_columns_immutable();
CREATE TRIGGER workflow_plan_v2_preparations_policy_immutable
BEFORE UPDATE ON workflow_plan_v2_activation_preparations
FOR EACH ROW EXECUTE FUNCTION automata_enforce_runtime_policy_columns_immutable();
CREATE TRIGGER workflow_plan_v2_publications_policy_immutable
BEFORE UPDATE ON workflow_plan_v2_activation_publications
FOR EACH ROW EXECUTE FUNCTION automata_enforce_runtime_policy_columns_immutable();
CREATE TRIGGER workflow_plan_v2_instances_policy_immutable
BEFORE UPDATE ON workflow_plan_v2_instances
FOR EACH ROW EXECUTE FUNCTION automata_enforce_runtime_policy_columns_immutable();
CREATE TRIGGER workflow_plan_v2_materialization_claims_policy_immutable
BEFORE UPDATE ON workflow_plan_v2_materialization_claims
FOR EACH ROW EXECUTE FUNCTION automata_enforce_runtime_policy_columns_immutable();
CREATE TRIGGER workflow_plan_v2_concrete_jobs_policy_immutable
BEFORE UPDATE ON workflow_plan_v2_concrete_jobs
FOR EACH ROW EXECUTE FUNCTION automata_enforce_runtime_policy_columns_immutable();

ALTER TABLE workflow_plan_v2_activation_preparation_claims
    ADD COLUMN runner_policy_digest BYTEA NOT NULL,
    ADD COLUMN runner_policy_object_key TEXT COLLATE "C" NOT NULL,
    ADD COLUMN runner_policy_size_bytes BIGINT NOT NULL,
    ADD COLUMN runner_policy_media_type TEXT COLLATE "C" NOT NULL,
    ADD COLUMN origin_selection_id UUID,
    ADD CONSTRAINT workflow_plan_v2_preparation_runner_policy_shape CHECK (
        octet_length(runner_policy_digest) = 32
        AND runner_policy_object_key =
            'github/runner-policy/v1/' || encode(runner_policy_digest, 'hex') || '.json'
        AND runner_policy_size_bytes BETWEEN 1 AND 65536
        AND runner_policy_media_type =
            'application/vnd.automata.github-runner-policy+json'
        AND (origin_selection_id IS NULL OR
             origin_selection_id <> '00000000-0000-0000-0000-000000000000'::UUID)
    );

CREATE FUNCTION automata_require_preparation_runner_policy_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.runner_policy_digest IS DISTINCT FROM OLD.runner_policy_digest
            OR NEW.runner_policy_object_key IS DISTINCT FROM OLD.runner_policy_object_key
            OR NEW.runner_policy_size_bytes IS DISTINCT FROM OLD.runner_policy_size_bytes
            OR NEW.runner_policy_media_type IS DISTINCT FROM OLD.runner_policy_media_type
        THEN
            RAISE EXCEPTION 'logical preparation runner policy is immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_runner_policy_immutable';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_plan_v2_jobs AS job
    JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = job.run_id
    JOIN github_workflow_run_subject_evidence AS subject
      ON subject.run_id = job.run_id
     AND subject.tenant_id = pin.tenant_id
     AND subject.repository_id = pin.repository_id
    JOIN github_provider_delivery_evidence AS delivery
      ON delivery.provider_delivery_id = subject.provider_delivery_id
     AND delivery.tenant_id = subject.tenant_id
     AND delivery.repository_id = subject.repository_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = delivery.tenant_id
     AND manifest.repository_id = delivery.repository_id
     AND manifest.provider_connection_id = delivery.provider_connection_id
     AND manifest.manifest_revision = delivery.provider_manifest_revision
     AND manifest.manifest_digest = delivery.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = pin.tenant_id
     AND policy.repository_id = pin.repository_id
     AND policy.policy_revision = pin.policy_revision
     AND policy.policy_digest = pin.policy_digest
     AND policy.state = 'sealed'
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
      AND NEW.runtime_policy_revision = pin.policy_revision
      AND NEW.runtime_policy_digest = pin.policy_digest
      AND manifest.runtime_policy_revision = pin.policy_revision
      AND manifest.runtime_policy_digest = pin.policy_digest
      AND NEW.runner_policy_digest = manifest.runner_policy_digest
      AND NEW.runner_policy_object_key = manifest.runner_policy_object_key
      AND NEW.runner_policy_size_bytes = manifest.runner_policy_size_bytes
      AND NEW.runner_policy_media_type = manifest.runner_policy_media_type
      AND NEW.runner_policy_digest = pg_catalog.sha256(policy.canonical_policy)
      AND NEW.runner_policy_size_bytes = pg_catalog.octet_length(policy.canonical_policy)
    FOR KEY SHARE OF job, pin, subject, delivery, manifest, policy;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'logical preparation runner policy lacks authenticated manifest provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_runner_policy_provenance';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_preparation_claims_01_runner_policy
BEFORE INSERT OR UPDATE ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW EXECUTE FUNCTION automata_require_preparation_runner_policy_provenance();

ALTER TABLE workflow_plan_v2_jobs
    ADD COLUMN activation_origin_selection_id UUID,
    ADD CONSTRAINT workflow_plan_v2_jobs_activation_origin_shape CHECK (
        activation_origin_selection_id IS NULL OR
        activation_origin_selection_id <> '00000000-0000-0000-0000-000000000000'::UUID
    );

-- Admission creates inert work only.  Activation authority may be acquired
-- exclusively by the selector's locked pending -> activating transition;
-- callers may not smuggle a fence or a partially/fully active claim through
-- the otherwise-authenticated graph-construction INSERT path.
CREATE FUNCTION automata_require_pristine_logical_job_admission()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state IS DISTINCT FROM 'pending'
        OR NEW.activation_fence IS DISTINCT FROM 0
        OR NEW.activation_owner_id IS NOT NULL
        OR NEW.activation_claimed_at_ms IS NOT NULL
        OR NEW.activation_expires_at_ms IS NOT NULL
        OR NEW.activation_input_digest IS NOT NULL
        OR NEW.authority_profile IS NOT NULL
        OR NEW.activation_origin_selection_id IS NOT NULL
    THEN
        RAISE EXCEPTION 'logical job admission must begin without activation authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_jobs_activation_admission_pristine';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Trigger names execute lexically.  This 00 guard deliberately precedes the
-- authenticated open-graph 01 guard, so malformed authority is classified by
-- the same exact constraint even if another admission precondition also fails.
CREATE TRIGGER workflow_plan_v2_jobs_00_activation_admission
BEFORE INSERT ON workflow_plan_v2_jobs
FOR EACH ROW EXECUTE FUNCTION automata_require_pristine_logical_job_admission();

ALTER TABLE workflow_plan_v2_materialization_claims
    ADD COLUMN origin_selection_id UUID,
    ADD CONSTRAINT workflow_plan_v2_materialization_origin_shape CHECK (
        origin_selection_id IS NULL OR
        origin_selection_id <> '00000000-0000-0000-0000-000000000000'::UUID
    );

CREATE TABLE workflow_plan_v2_work_selection_replay_horizons (
    queue_name TEXT PRIMARY KEY,
    replay_floor_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    cursor_ready_at_ms BIGINT,
    cursor_run_id UUID,
    cursor_invocation_id UUID,
    cursor_source_order INTEGER,
    cursor_matrix_index INTEGER,
    cursor_target_id UUID,
    CONSTRAINT workflow_plan_v2_work_selection_horizon_queue CHECK (
        queue_name IN ('activation', 'materialization')
    ),
    CONSTRAINT workflow_plan_v2_work_selection_horizon_time CHECK (
        replay_floor_ms >= 0 AND updated_at_ms >= replay_floor_ms
    ),
    CONSTRAINT workflow_plan_v2_work_selection_horizon_cursor CHECK (
        (cursor_ready_at_ms IS NULL
         AND cursor_run_id IS NULL AND cursor_invocation_id IS NULL
         AND cursor_source_order IS NULL AND cursor_matrix_index IS NULL
         AND cursor_target_id IS NULL)
        OR (cursor_ready_at_ms >= 0
            AND cursor_run_id IS NOT NULL
            AND cursor_invocation_id IS NOT NULL
            AND cursor_source_order BETWEEN 0 AND 1023
            AND cursor_target_id IS NOT NULL
            AND ((queue_name = 'activation' AND cursor_matrix_index IS NULL)
                 OR (queue_name = 'materialization'
                     AND cursor_matrix_index BETWEEN 0 AND 255)))
    )
);

INSERT INTO workflow_plan_v2_work_selection_replay_horizons (
    queue_name, replay_floor_ms, updated_at_ms
)
SELECT queue_name, greatest(0, now_ms - 60000), now_ms
FROM (
    SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
) AS clock
CROSS JOIN (VALUES ('activation'), ('materialization')) AS queue(queue_name);

CREATE TABLE workflow_plan_v2_activation_work_selections (
    selection_id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    requested_at_ms BIGINT NOT NULL,
    duration_ms BIGINT NOT NULL,
    claimed_at_ms BIGINT,
    expires_at_ms BIGINT,
    outcome TEXT NOT NULL,
    tenant_id TEXT,
    run_id UUID,
    invocation_id UUID,
    logical_job_id UUID,
    generation BIGINT,
    authority_kind TEXT,
    authority_digest BYTEA,
    CONSTRAINT workflow_plan_v2_activation_selection_identity CHECK (
        selection_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND requested_at_ms >= 0 AND duration_ms BETWEEN 2000 AND 300000
    ),
    CONSTRAINT workflow_plan_v2_activation_selection_shape CHECK ((
        (outcome = 'selecting' AND claimed_at_ms IS NULL AND expires_at_ms IS NULL
         AND tenant_id IS NULL AND run_id IS NULL AND invocation_id IS NULL
         AND logical_job_id IS NULL AND generation IS NULL
         AND authority_kind IS NULL AND authority_digest IS NULL)
        OR (outcome IN ('idle', 'contended', 'claimed', 'quarantined')
            AND claimed_at_ms >= 0
            AND expires_at_ms = claimed_at_ms + duration_ms
            AND ((outcome IN ('idle', 'contended')
                  AND tenant_id IS NULL AND run_id IS NULL
                  AND invocation_id IS NULL AND logical_job_id IS NULL
                  AND generation IS NULL AND authority_kind IS NULL
                  AND authority_digest IS NULL)
                 OR (outcome IN ('claimed', 'quarantined')
                     AND tenant_id IS NOT NULL AND run_id IS NOT NULL
                     AND invocation_id IS NOT NULL AND logical_job_id IS NOT NULL
                     AND generation > 0
                     AND authority_kind IN ('preparation', 'activation')
                     AND octet_length(authority_digest) = 32)))
    ) IS TRUE)
);

CREATE TABLE workflow_plan_v2_materialization_work_selections (
    selection_id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    requested_at_ms BIGINT NOT NULL,
    duration_ms BIGINT NOT NULL,
    claimed_at_ms BIGINT,
    expires_at_ms BIGINT,
    outcome TEXT NOT NULL,
    tenant_id TEXT,
    run_id UUID,
    invocation_id UUID,
    logical_job_id UUID,
    instance_id UUID,
    generation BIGINT,
    authority_digest BYTEA,
    CONSTRAINT workflow_plan_v2_materialization_selection_identity CHECK (
        selection_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND requested_at_ms >= 0 AND duration_ms BETWEEN 2000 AND 300000
    ),
    CONSTRAINT workflow_plan_v2_materialization_selection_shape CHECK ((
        (outcome = 'selecting' AND claimed_at_ms IS NULL AND expires_at_ms IS NULL
         AND tenant_id IS NULL AND run_id IS NULL AND invocation_id IS NULL
         AND logical_job_id IS NULL AND instance_id IS NULL AND generation IS NULL
         AND authority_digest IS NULL)
        OR (outcome IN ('idle', 'contended', 'claimed', 'quarantined')
            AND claimed_at_ms >= 0
            AND expires_at_ms = claimed_at_ms + duration_ms
            AND ((outcome IN ('idle', 'contended')
                  AND tenant_id IS NULL AND run_id IS NULL
                  AND invocation_id IS NULL AND logical_job_id IS NULL
                  AND instance_id IS NULL AND generation IS NULL
                  AND authority_digest IS NULL)
                 OR (outcome IN ('claimed', 'quarantined')
                     AND tenant_id IS NOT NULL AND run_id IS NOT NULL
                     AND invocation_id IS NOT NULL AND logical_job_id IS NOT NULL
                     AND instance_id IS NOT NULL AND generation > 0
                     AND octet_length(authority_digest) = 32)))
    ) IS TRUE)
);

CREATE INDEX workflow_plan_v2_activation_selection_expiry
    ON workflow_plan_v2_activation_work_selections(
        expires_at_ms, requested_at_ms, selection_id
    ) WHERE outcome <> 'selecting';
CREATE INDEX workflow_plan_v2_materialization_selection_expiry
    ON workflow_plan_v2_materialization_work_selections(
        expires_at_ms, requested_at_ms, selection_id
    ) WHERE outcome <> 'selecting';
CREATE INDEX workflow_plan_v2_activation_selection_target
    ON workflow_plan_v2_activation_work_selections(
        logical_job_id, expires_at_ms, selection_id
    ) WHERE outcome = 'claimed';
CREATE INDEX workflow_plan_v2_materialization_selection_target
    ON workflow_plan_v2_materialization_work_selections(
        instance_id, expires_at_ms, selection_id
    ) WHERE outcome = 'claimed';
CREATE UNIQUE INDEX workflow_plan_v2_activation_selection_generation
    ON workflow_plan_v2_activation_work_selections(
        logical_job_id, authority_kind, generation
    ) WHERE outcome = 'claimed';
CREATE UNIQUE INDEX workflow_plan_v2_materialization_selection_generation
    ON workflow_plan_v2_materialization_work_selections(instance_id, generation)
    WHERE outcome = 'claimed';

CREATE TABLE workflow_plan_v2_activation_work_quarantines (
    logical_job_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    selection_id UUID NOT NULL,
    selection_owner_id UUID NOT NULL,
    selection_requested_at_ms BIGINT NOT NULL,
    selection_duration_ms BIGINT NOT NULL,
    selection_generation BIGINT NOT NULL,
    selection_claimed_at_ms BIGINT NOT NULL,
    selection_expires_at_ms BIGINT NOT NULL,
    authority_kind TEXT NOT NULL,
    authority_digest BYTEA NOT NULL,
    authority_owner_id UUID NOT NULL,
    authority_generation BIGINT NOT NULL,
    authority_claimed_at_ms BIGINT NOT NULL,
    authority_expires_at_ms BIGINT NOT NULL,
    failure_kind TEXT NOT NULL,
    quarantined_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_activation_quarantine_target_fk FOREIGN KEY (
        run_id, invocation_id, logical_job_id
    ) REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_activation_quarantine_selection_fk FOREIGN KEY (selection_id)
        REFERENCES workflow_plan_v2_activation_work_selections(selection_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_activation_quarantine_selection_unique UNIQUE (selection_id),
    CONSTRAINT workflow_plan_v2_activation_quarantine_shape CHECK (
        selection_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND selection_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND authority_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND selection_generation > 0 AND authority_generation >= selection_generation
        AND selection_requested_at_ms >= 0
        AND selection_duration_ms BETWEEN 2000 AND 300000
        AND selection_claimed_at_ms >= 0
        AND selection_expires_at_ms =
            selection_claimed_at_ms + selection_duration_ms
        AND authority_kind IN ('preparation', 'activation')
        AND octet_length(authority_digest) = 32
        AND authority_claimed_at_ms >= 0
        AND authority_expires_at_ms > authority_claimed_at_ms
        AND failure_kind IN (
            'relational_evidence', 'object_evidence', 'payload_evidence',
            'generation_exhausted'
        )
        AND quarantined_at_ms >= 0
    )
);

CREATE TABLE workflow_plan_v2_materialization_work_quarantines (
    instance_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    selection_id UUID NOT NULL,
    selection_owner_id UUID NOT NULL,
    selection_requested_at_ms BIGINT NOT NULL,
    selection_duration_ms BIGINT NOT NULL,
    selection_generation BIGINT NOT NULL,
    selection_claimed_at_ms BIGINT NOT NULL,
    selection_expires_at_ms BIGINT NOT NULL,
    authority_digest BYTEA NOT NULL,
    authority_owner_id UUID NOT NULL,
    authority_generation BIGINT NOT NULL,
    authority_claimed_at_ms BIGINT NOT NULL,
    authority_expires_at_ms BIGINT NOT NULL,
    failure_kind TEXT NOT NULL,
    quarantined_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_materialization_quarantine_target_fk FOREIGN KEY (
        run_id, invocation_id, logical_job_id, instance_id
    ) REFERENCES workflow_plan_v2_instances(
        run_id, invocation_id, logical_job_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_materialization_quarantine_selection_fk FOREIGN KEY (selection_id)
        REFERENCES workflow_plan_v2_materialization_work_selections(selection_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_materialization_quarantine_selection_unique UNIQUE (selection_id),
    CONSTRAINT workflow_plan_v2_materialization_quarantine_shape CHECK (
        selection_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND selection_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND authority_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND selection_generation > 0 AND authority_generation >= selection_generation
        AND selection_requested_at_ms >= 0
        AND selection_duration_ms BETWEEN 2000 AND 300000
        AND selection_claimed_at_ms >= 0
        AND selection_expires_at_ms =
            selection_claimed_at_ms + selection_duration_ms
        AND octet_length(authority_digest) = 32
        AND authority_claimed_at_ms >= 0
        AND authority_expires_at_ms > authority_claimed_at_ms
        AND failure_kind IN (
            'relational_evidence', 'object_evidence', 'payload_evidence',
            'generation_exhausted'
        )
        AND quarantined_at_ms >= 0
    )
);

-- A renewal request is identified by its complete predecessor fence and
-- requested database-issued duration.  These immutable receipts make an
-- acknowledgement-loss retry exact even after the target has advanced again.
-- They are retained with the bounded selection receipt and cascade only when
-- that receipt passes the replay-horizon cleanup guard.
CREATE TABLE workflow_plan_v2_activation_renewal_receipts (
    logical_job_id UUID NOT NULL,
    authority_kind TEXT NOT NULL,
    selection_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    runtime_policy_revision BIGINT NOT NULL,
    runtime_policy_digest BYTEA NOT NULL,
    authority_digest BYTEA NOT NULL,
    predecessor_generation BIGINT NOT NULL,
    predecessor_claimed_at_ms BIGINT NOT NULL,
    predecessor_expires_at_ms BIGINT NOT NULL,
    requested_duration_ms BIGINT NOT NULL,
    successor_generation BIGINT NOT NULL,
    successor_claimed_at_ms BIGINT NOT NULL,
    successor_expires_at_ms BIGINT NOT NULL,
    validated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_activation_renewal_receipts_pk PRIMARY KEY (
        logical_job_id, authority_kind, predecessor_generation
    ),
    CONSTRAINT workflow_plan_v2_activation_renewal_selection_unique UNIQUE (
        selection_id, authority_kind, logical_job_id, predecessor_generation
    ),
    CONSTRAINT workflow_plan_v2_activation_renewal_selection_fk
        FOREIGN KEY (selection_id)
        REFERENCES workflow_plan_v2_activation_work_selections(selection_id)
        ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_activation_renewal_target_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_activation_renewal_shape CHECK (
        authority_kind IN ('preparation', 'activation')
        AND selection_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND runtime_policy_revision > 0
        AND octet_length(runtime_policy_digest) = 32
        AND octet_length(authority_digest) = 32
        AND predecessor_generation > 0
        AND successor_generation = predecessor_generation + 1
        AND predecessor_claimed_at_ms >= 0
        AND predecessor_expires_at_ms > predecessor_claimed_at_ms
        AND requested_duration_ms BETWEEN 2000 AND 900000
        AND successor_claimed_at_ms >= predecessor_claimed_at_ms
        AND successor_claimed_at_ms < predecessor_expires_at_ms
        AND successor_expires_at_ms =
            successor_claimed_at_ms + requested_duration_ms
        AND successor_expires_at_ms > predecessor_expires_at_ms
        AND validated_at_ms >= successor_claimed_at_ms
        AND validated_at_ms < successor_expires_at_ms
    )
);

CREATE TABLE workflow_plan_v2_materialization_renewal_receipts (
    instance_id UUID NOT NULL,
    selection_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    runtime_policy_revision BIGINT NOT NULL,
    runtime_policy_digest BYTEA NOT NULL,
    authority_digest BYTEA NOT NULL,
    expected_job_id UUID NOT NULL,
    expected_attempt_id UUID NOT NULL,
    predecessor_generation BIGINT NOT NULL,
    predecessor_claimed_at_ms BIGINT NOT NULL,
    predecessor_expires_at_ms BIGINT NOT NULL,
    requested_duration_ms BIGINT NOT NULL,
    successor_generation BIGINT NOT NULL,
    successor_claimed_at_ms BIGINT NOT NULL,
    successor_expires_at_ms BIGINT NOT NULL,
    validated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_materialization_renewal_receipts_pk PRIMARY KEY (
        instance_id, predecessor_generation
    ),
    CONSTRAINT workflow_plan_v2_materialization_renewal_selection_unique UNIQUE (
        selection_id, instance_id, predecessor_generation
    ),
    CONSTRAINT workflow_plan_v2_materialization_renewal_selection_fk
        FOREIGN KEY (selection_id)
        REFERENCES workflow_plan_v2_materialization_work_selections(selection_id)
        ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_materialization_renewal_target_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id, instance_id)
        REFERENCES workflow_plan_v2_instances(
            run_id, invocation_id, logical_job_id, id
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_materialization_renewal_shape CHECK (
        selection_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND expected_job_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND expected_attempt_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND runtime_policy_revision > 0
        AND octet_length(runtime_policy_digest) = 32
        AND octet_length(authority_digest) = 32
        AND predecessor_generation > 0
        AND successor_generation = predecessor_generation + 1
        AND predecessor_claimed_at_ms >= 0
        AND predecessor_expires_at_ms > predecessor_claimed_at_ms
        AND requested_duration_ms BETWEEN 2000 AND 900000
        AND successor_claimed_at_ms >= predecessor_claimed_at_ms
        AND successor_claimed_at_ms < predecessor_expires_at_ms
        AND successor_expires_at_ms =
            successor_claimed_at_ms + requested_duration_ms
        AND successor_expires_at_ms > predecessor_expires_at_ms
        AND validated_at_ms >= successor_claimed_at_ms
        AND validated_at_ms < successor_expires_at_ms
    )
);

CREATE FUNCTION automata_reject_workflow_work_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow work-selection evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'workflow_work_selection_evidence_immutable';
END;
$automata$;

CREATE FUNCTION automata_enforce_workflow_work_selection_horizon()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT;
    expected_floor BIGINT;
    cursor_exact BOOLEAN := TRUE;
BEGIN
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    expected_floor := greatest(
        OLD.replay_floor_ms,
        least(
            OLD.replay_floor_ms + (NEW.updated_at_ms - OLD.updated_at_ms),
            greatest(0, NEW.updated_at_ms - 60000)
        )
    );
    IF NEW.cursor_target_id IS NOT NULL THEN
        IF NEW.queue_name = 'activation' THEN
            SELECT EXISTS (
                SELECT 1
                FROM workflow_plan_v2_jobs AS job
                WHERE job.id = NEW.cursor_target_id
                  AND job.run_id = NEW.cursor_run_id
                  AND job.invocation_id = NEW.cursor_invocation_id
                  AND job.source_order = NEW.cursor_source_order
                  AND job.created_at_ms = NEW.cursor_ready_at_ms
            ) INTO cursor_exact;
        ELSE
            SELECT EXISTS (
                SELECT 1
                FROM workflow_plan_v2_instances AS instance
                JOIN workflow_plan_v2_jobs AS job
                  ON job.run_id = instance.run_id
                 AND job.invocation_id = instance.invocation_id
                 AND job.id = instance.logical_job_id
                JOIN workflow_plan_v2_activation_publications AS publication
                  ON publication.run_id = instance.run_id
                 AND publication.invocation_id = instance.invocation_id
                 AND publication.logical_job_id = instance.logical_job_id
                WHERE instance.id = NEW.cursor_target_id
                  AND instance.run_id = NEW.cursor_run_id
                  AND instance.invocation_id = NEW.cursor_invocation_id
                  AND job.source_order = NEW.cursor_source_order
                  AND instance.matrix_index = NEW.cursor_matrix_index
                  AND publication.published_at_ms = NEW.cursor_ready_at_ms
            ) INTO cursor_exact;
        END IF;
    END IF;
    IF NEW.queue_name IS DISTINCT FROM OLD.queue_name
        OR OLD.updated_at_ms > database_now
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.updated_at_ms > database_now
        OR database_now - NEW.updated_at_ms > 60000
        OR NEW.replay_floor_ms IS DISTINCT FROM expected_floor
        OR cursor_exact IS DISTINCT FROM TRUE
    THEN
        RAISE EXCEPTION 'workflow work-selection replay horizon transition is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_work_selection_horizon_advance';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_enforce_activation_selection_receipt_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    replay_floor BIGINT;
    live_origin BOOLEAN := FALSE;
BEGIN
    SELECT replay_floor_ms INTO replay_floor
    FROM workflow_plan_v2_work_selection_replay_horizons
    WHERE queue_name = 'activation'
    FOR UPDATE;
    SELECT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_preparation_claims AS claim
        WHERE OLD.authority_kind = 'preparation'
          AND claim.logical_job_id = OLD.logical_job_id
          AND claim.origin_selection_id = OLD.selection_id
          AND claim.state = 'preparing'
        UNION ALL
        SELECT 1
        FROM workflow_plan_v2_jobs AS job
        WHERE OLD.authority_kind = 'activation'
          AND job.id = OLD.logical_job_id
          AND job.activation_origin_selection_id = OLD.selection_id
          AND job.state = 'activating'
    ) INTO live_origin;
    IF replay_floor IS NULL OR OLD.outcome = 'selecting'
        OR OLD.expires_at_ms > replay_floor
        OR OLD.requested_at_ms >= replay_floor
        OR live_origin
    THEN
        RAISE EXCEPTION 'activation selection receipt remains inside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_receipt_retained';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE FUNCTION automata_enforce_materialization_selection_receipt_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    replay_floor BIGINT;
    live_origin BOOLEAN := FALSE;
BEGIN
    SELECT replay_floor_ms INTO replay_floor
    FROM workflow_plan_v2_work_selection_replay_horizons
    WHERE queue_name = 'materialization'
    FOR UPDATE;
    SELECT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_materialization_claims AS claim
        WHERE claim.instance_id = OLD.instance_id
          AND claim.origin_selection_id = OLD.selection_id
          AND claim.state = 'materializing'
    ) INTO live_origin;
    IF replay_floor IS NULL OR OLD.outcome = 'selecting'
        OR OLD.expires_at_ms > replay_floor
        OR OLD.requested_at_ms >= replay_floor
        OR live_origin
    THEN
        RAISE EXCEPTION 'materialization selection receipt remains inside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_receipt_retained';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE FUNCTION automata_validate_activation_work_selection_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT;
    replay_floor BIGINT;
    exact_evidence BOOLEAN := FALSE;
    ready_exists BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.outcome <> 'selecting' THEN
            RAISE EXCEPTION 'activation selection must begin as a provisional reservation'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_selection_reservation_first';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.outcome <> 'selecting'
        OR NEW.selection_id IS DISTINCT FROM OLD.selection_id
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.requested_at_ms IS DISTINCT FROM OLD.requested_at_ms
        OR NEW.duration_ms IS DISTINCT FROM OLD.duration_ms
        OR NEW.outcome = 'selecting'
    THEN
        RAISE EXCEPTION 'activation selection transition is immutable or invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_transition';
    END IF;
    SELECT replay_floor_ms INTO replay_floor
    FROM workflow_plan_v2_work_selection_replay_horizons
    WHERE queue_name = 'activation'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'activation selection replay authority is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_horizon_required';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NEW.requested_at_ms <= replay_floor
        OR NEW.requested_at_ms < database_now - 60000
        OR NEW.requested_at_ms > database_now + 60000
    THEN
        RAISE EXCEPTION 'activation selection request is outside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_request_time';
    END IF;
    IF NEW.claimed_at_ms > database_now
        OR database_now - NEW.claimed_at_ms > 60000
        OR (NEW.outcome <> 'quarantined' AND (
            NEW.expires_at_ms <= database_now
            OR NEW.expires_at_ms - database_now < 1000
        ))
    THEN
        RAISE EXCEPTION 'activation selection issue time is not database-current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_database_time';
    END IF;

    IF NEW.outcome = 'claimed' AND NEW.authority_kind = 'preparation' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_preparation_claims AS claim
            JOIN workflow_plan_v2_jobs AS job ON job.id = claim.logical_job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE claim.logical_job_id = NEW.logical_job_id
              AND repository.tenant_id = NEW.tenant_id
              AND job.run_id = NEW.run_id
              AND job.invocation_id = NEW.invocation_id
              AND claim.origin_selection_id = NEW.selection_id
              AND claim.owner_id = NEW.owner_id
              AND claim.generation = NEW.generation
              AND claim.descriptor_digest = NEW.authority_digest
              AND claim.claimed_at_ms = NEW.claimed_at_ms
              AND claim.expires_at_ms = NEW.expires_at_ms
              AND claim.state = 'preparing'
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'claimed' AND NEW.authority_kind = 'activation' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_jobs AS job
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE job.id = NEW.logical_job_id
              AND repository.tenant_id = NEW.tenant_id
              AND job.run_id = NEW.run_id
              AND job.invocation_id = NEW.invocation_id
              AND job.activation_origin_selection_id = NEW.selection_id
              AND job.activation_owner_id = NEW.owner_id
              AND job.activation_fence = NEW.generation
              AND job.activation_input_digest = NEW.authority_digest
              AND job.activation_claimed_at_ms = NEW.claimed_at_ms
              AND job.activation_expires_at_ms = NEW.expires_at_ms
              AND job.state = 'activating'
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_work_quarantines AS quarantine
            WHERE quarantine.logical_job_id = NEW.logical_job_id
              AND quarantine.tenant_id = NEW.tenant_id
              AND quarantine.run_id = NEW.run_id
              AND quarantine.invocation_id = NEW.invocation_id
              AND quarantine.selection_id = NEW.selection_id
              AND quarantine.selection_owner_id = NEW.owner_id
              AND quarantine.selection_requested_at_ms = NEW.requested_at_ms
              AND quarantine.selection_duration_ms = NEW.duration_ms
              AND quarantine.selection_generation = NEW.generation
              AND quarantine.selection_claimed_at_ms = NEW.claimed_at_ms
              AND quarantine.selection_expires_at_ms = NEW.expires_at_ms
              AND quarantine.authority_kind = NEW.authority_kind
              AND quarantine.authority_digest = NEW.authority_digest
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'contended' THEN
        exact_evidence := TRUE;
    ELSE
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_jobs AS job
            JOIN workflow_plan_v2_invocations AS invocation
              ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
            JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            LEFT JOIN workflow_plan_v2_activation_preparation_claims AS preparation
              ON preparation.logical_job_id = job.id
            LEFT JOIN workflow_plan_v2_activation_work_quarantines AS quarantine
              ON quarantine.logical_job_id = job.id
            WHERE job.execution_kind = 'steps'
              AND invocation.id = marker.root_invocation_id
              AND invocation.state IN ('pending', 'active')
              AND marker.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress')
              AND quarantine.logical_job_id IS NULL
              AND ((job.state = 'pending' AND (
                  preparation.logical_job_id IS NULL OR preparation.state = 'prepared'
                  OR (preparation.state = 'preparing'
                      AND preparation.expires_at_ms <= NEW.claimed_at_ms)
              )) OR (job.state = 'activating'
                     AND job.activation_expires_at_ms <= NEW.claimed_at_ms))
              AND NOT EXISTS (
                  SELECT 1
                  FROM workflow_plan_v2_dependencies AS dependency
                  LEFT JOIN workflow_plan_v2_job_result_claims AS result_claim
                    ON result_claim.logical_job_id = dependency.prerequisite_job_id
                   AND result_claim.state = 'finalized'
                  WHERE dependency.run_id = job.run_id
                    AND dependency.invocation_id = job.invocation_id
                    AND dependency.logical_job_id = job.id
                    AND result_claim.logical_job_id IS NULL
              )
        ) INTO ready_exists;
        exact_evidence := NOT ready_exists;
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'activation selection lacks exact durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_receipt_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_validate_materialization_work_selection_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT;
    replay_floor BIGINT;
    exact_evidence BOOLEAN := FALSE;
    ready_exists BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.outcome <> 'selecting' THEN
            RAISE EXCEPTION 'materialization selection must begin as a provisional reservation'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_selection_reservation_first';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.outcome <> 'selecting'
        OR NEW.selection_id IS DISTINCT FROM OLD.selection_id
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.requested_at_ms IS DISTINCT FROM OLD.requested_at_ms
        OR NEW.duration_ms IS DISTINCT FROM OLD.duration_ms
        OR NEW.outcome = 'selecting'
    THEN
        RAISE EXCEPTION 'materialization selection transition is immutable or invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_transition';
    END IF;
    SELECT replay_floor_ms INTO replay_floor
    FROM workflow_plan_v2_work_selection_replay_horizons
    WHERE queue_name = 'materialization'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'materialization selection replay authority is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_horizon_required';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NEW.requested_at_ms <= replay_floor
        OR NEW.requested_at_ms < database_now - 60000
        OR NEW.requested_at_ms > database_now + 60000
    THEN
        RAISE EXCEPTION 'materialization selection request is outside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_request_time';
    END IF;
    IF NEW.claimed_at_ms > database_now
        OR database_now - NEW.claimed_at_ms > 60000
        OR (NEW.outcome <> 'quarantined' AND (
            NEW.expires_at_ms <= database_now
            OR NEW.expires_at_ms - database_now < 1000
        ))
    THEN
        RAISE EXCEPTION 'materialization selection issue time is not database-current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_database_time';
    END IF;

    IF NEW.outcome = 'claimed' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_materialization_claims AS claim
            JOIN workflow_plan_v2_instances AS instance ON instance.id = claim.instance_id
            JOIN workflow_runs AS run ON run.id = instance.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE claim.instance_id = NEW.instance_id
              AND repository.tenant_id = NEW.tenant_id
              AND instance.run_id = NEW.run_id
              AND instance.invocation_id = NEW.invocation_id
              AND instance.logical_job_id = NEW.logical_job_id
              AND claim.origin_selection_id = NEW.selection_id
              AND claim.owner_id = NEW.owner_id
              AND claim.generation = NEW.generation
              AND claim.descriptor_digest = NEW.authority_digest
              AND claim.claimed_at_ms = NEW.claimed_at_ms
              AND claim.expires_at_ms = NEW.expires_at_ms
              AND claim.state = 'materializing'
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_materialization_work_quarantines AS quarantine
            WHERE quarantine.instance_id = NEW.instance_id
              AND quarantine.tenant_id = NEW.tenant_id
              AND quarantine.run_id = NEW.run_id
              AND quarantine.invocation_id = NEW.invocation_id
              AND quarantine.logical_job_id = NEW.logical_job_id
              AND quarantine.selection_id = NEW.selection_id
              AND quarantine.selection_owner_id = NEW.owner_id
              AND quarantine.selection_requested_at_ms = NEW.requested_at_ms
              AND quarantine.selection_duration_ms = NEW.duration_ms
              AND quarantine.selection_generation = NEW.generation
              AND quarantine.selection_claimed_at_ms = NEW.claimed_at_ms
              AND quarantine.selection_expires_at_ms = NEW.expires_at_ms
              AND quarantine.authority_digest = NEW.authority_digest
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'contended' THEN
        exact_evidence := TRUE;
    ELSE
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_instances AS instance
            JOIN workflow_plan_v2_activation_publications AS publication
              ON publication.run_id = instance.run_id
             AND publication.invocation_id = instance.invocation_id
             AND publication.logical_job_id = instance.logical_job_id
            JOIN workflow_plan_v2_jobs AS job ON job.id = instance.logical_job_id
            JOIN workflow_plan_v2_invocations AS invocation
              ON invocation.run_id = instance.run_id
             AND invocation.id = instance.invocation_id
            JOIN workflow_plan_v2_runs AS marker ON marker.run_id = instance.run_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            LEFT JOIN workflow_plan_v2_materialization_claims AS claim
              ON claim.instance_id = instance.id
            LEFT JOIN workflow_plan_v2_materialization_work_quarantines AS quarantine
              ON quarantine.instance_id = instance.id
            WHERE publication.condition_matched
              AND publication.instance_count > 0
              AND job.state = 'activated'
              AND invocation.state IN ('pending', 'active')
              AND marker.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress')
              AND quarantine.instance_id IS NULL
              AND (claim.instance_id IS NULL OR (
                  claim.state = 'materializing'
                  AND claim.expires_at_ms <= NEW.claimed_at_ms
              ))
        ) INTO ready_exists;
        exact_evidence := NOT ready_exists;
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'materialization selection lacks exact durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_receipt_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Every live phase mutation shares cancellation and quarantine custody. The
-- adapter takes these locks in run -> marker -> invocation -> target order;
-- this function is defense in depth for direct SQL writers and retains each
-- share lock through transaction end.
CREATE FUNCTION automata_require_active_unquarantined_workflow_phase(
    target_run_id UUID,
    target_invocation_id UUID,
    target_logical_job_id UUID,
    target_instance_id UUID
)
RETURNS void
LANGUAGE plpgsql
AS $automata$
DECLARE
    graph_active BOOLEAN;
BEGIN
    SELECT run.status IN ('queued', 'in_progress')
           AND run.admission_epoch = 4
           AND run.plan_schema = 2
      INTO graph_active
    FROM workflow_runs AS run
    WHERE run.id = target_run_id
    FOR SHARE OF run;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires an active run'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_run_active';
    END IF;

    SELECT marker.state IN ('pending', 'active')
           AND marker.orchestration_schema = 1
           AND marker.admission_graph_sealed_at_ms IS NOT NULL
           AND marker.root_invocation_id = target_invocation_id
      INTO graph_active
    FROM workflow_plan_v2_runs AS marker
    WHERE marker.run_id = target_run_id
    FOR SHARE OF marker;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires an active sealed marker'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_marker_active';
    END IF;

    SELECT invocation.state IN ('pending', 'active')
           AND invocation.plan_schema = 2
      INTO graph_active
    FROM workflow_plan_v2_invocations AS invocation
    WHERE invocation.run_id = target_run_id
      AND invocation.id = target_invocation_id
    FOR SHARE OF invocation;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires an active invocation'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_invocation_active';
    END IF;

    SELECT TRUE INTO graph_active
    FROM workflow_plan_v2_jobs AS job
    WHERE job.run_id = target_run_id
      AND job.invocation_id = target_invocation_id
      AND job.id = target_logical_job_id
    FOR SHARE OF job;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires its exact logical job'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_logical_job_exact';
    END IF;

    IF target_instance_id IS NOT NULL THEN
        SELECT TRUE INTO graph_active
        FROM workflow_plan_v2_instances AS instance
        WHERE instance.id = target_instance_id
          AND instance.run_id = target_run_id
          AND instance.invocation_id = target_invocation_id
          AND instance.logical_job_id = target_logical_job_id
        FOR SHARE OF instance;
        IF graph_active IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'workflow phase mutation requires its exact instance'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_phase_instance_exact';
        END IF;
    END IF;

    IF target_instance_id IS NULL THEN
        PERFORM 1
        FROM workflow_plan_v2_activation_work_quarantines AS quarantine
        WHERE quarantine.logical_job_id = target_logical_job_id
        FOR SHARE OF quarantine;
    ELSE
        PERFORM 1
        FROM workflow_plan_v2_materialization_work_quarantines AS quarantine
        WHERE quarantine.instance_id = target_instance_id
        FOR SHARE OF quarantine;
    END IF;
    IF FOUND THEN
        RAISE EXCEPTION 'workflow phase mutation is quarantined'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_quarantine_dominates';
    END IF;
END;
$automata$;

CREATE FUNCTION automata_validate_activation_real_claim_quarantine()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT;
    receipt workflow_plan_v2_activation_work_selections%ROWTYPE;
    existing_quarantine workflow_plan_v2_activation_work_quarantines%ROWTYPE;
    authority RECORD;
    internal_poison BOOLEAN := FALSE;
BEGIN
    SELECT * INTO receipt
    FROM workflow_plan_v2_activation_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    PERFORM 1
    FROM workflow_plan_v2_work_selection_replay_horizons
    WHERE queue_name = 'activation'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'activation quarantine replay horizon is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_horizon_required';
    END IF;
    SELECT * INTO existing_quarantine
    FROM workflow_plan_v2_activation_work_quarantines
    WHERE logical_job_id = NEW.logical_job_id
    FOR UPDATE;
    IF existing_quarantine.logical_job_id IS NOT NULL THEN
        RAISE EXCEPTION 'activation quarantine already has immutable evidence'
            USING ERRCODE = 'unique_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_already_exists';
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
    );

    IF NEW.authority_kind = 'preparation' THEN
        SELECT repository.tenant_id, job.run_id, job.invocation_id,
               claim.origin_selection_id, claim.owner_id, claim.generation,
               claim.descriptor_digest AS digest, claim.claimed_at_ms,
               claim.expires_at_ms, claim.state
          INTO authority
        FROM workflow_plan_v2_activation_preparation_claims AS claim
        JOIN workflow_plan_v2_jobs AS job ON job.id = claim.logical_job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE claim.logical_job_id = NEW.logical_job_id
        FOR UPDATE OF claim, job;
    ELSE
        SELECT repository.tenant_id, job.run_id, job.invocation_id,
               job.activation_origin_selection_id AS origin_selection_id,
               job.activation_owner_id AS owner_id,
               job.activation_fence AS generation,
               job.activation_input_digest AS digest,
               job.activation_claimed_at_ms AS claimed_at_ms,
               job.activation_expires_at_ms AS expires_at_ms,
               job.state
          INTO authority
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE job.id = NEW.logical_job_id
        FOR UPDATE OF job;
    END IF;

    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    internal_poison := NEW.failure_kind = 'generation_exhausted'
        AND receipt.outcome = 'selecting';
    IF receipt.selection_id IS NULL
        OR receipt.owner_id IS DISTINCT FROM NEW.selection_owner_id
        OR receipt.requested_at_ms IS DISTINCT FROM NEW.selection_requested_at_ms
        OR receipt.duration_ms IS DISTINCT FROM NEW.selection_duration_ms
    THEN
        RAISE EXCEPTION 'activation quarantine lacks its exact selection request'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_selection_request_exact';
    END IF;
    IF internal_poison THEN
        IF receipt.claimed_at_ms IS NOT NULL OR receipt.expires_at_ms IS NOT NULL
            OR receipt.tenant_id IS NOT NULL OR receipt.run_id IS NOT NULL
            OR receipt.invocation_id IS NOT NULL OR receipt.logical_job_id IS NOT NULL
            OR receipt.generation IS NOT NULL OR receipt.authority_kind IS NOT NULL
            OR receipt.authority_digest IS NOT NULL
            OR NEW.selection_generation <> NEW.authority_generation
            OR NEW.selection_claimed_at_ms > database_now
            OR database_now - NEW.selection_claimed_at_ms > 60000
            OR NEW.selection_expires_at_ms - database_now < 1000
            OR NEW.authority_generation <> 9223372036854775807
            OR NEW.authority_expires_at_ms > database_now
        THEN
            RAISE EXCEPTION 'activation generation poison is not an exact provisional capture'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_quarantine_generation_poison_exact';
        END IF;
    ELSIF NEW.failure_kind = 'generation_exhausted'
        OR receipt.outcome <> 'claimed'
        OR receipt.claimed_at_ms IS DISTINCT FROM NEW.selection_claimed_at_ms
        OR receipt.expires_at_ms IS DISTINCT FROM NEW.selection_expires_at_ms
        OR receipt.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR receipt.run_id IS DISTINCT FROM NEW.run_id
        OR receipt.invocation_id IS DISTINCT FROM NEW.invocation_id
        OR receipt.logical_job_id IS DISTINCT FROM NEW.logical_job_id
        OR receipt.generation IS DISTINCT FROM NEW.selection_generation
        OR receipt.authority_kind IS DISTINCT FROM NEW.authority_kind
        OR receipt.authority_digest IS DISTINCT FROM NEW.authority_digest
    THEN
        RAISE EXCEPTION 'activation quarantine lacks the exact claimed receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_selection_exact';
    END IF;

    IF authority IS NULL
        OR (authority.tenant_id, authority.run_id, authority.invocation_id)
           IS DISTINCT FROM (NEW.tenant_id, NEW.run_id, NEW.invocation_id)
        OR authority.owner_id IS DISTINCT FROM NEW.authority_owner_id
        OR authority.generation IS DISTINCT FROM NEW.authority_generation
        OR authority.generation < NEW.selection_generation
        OR authority.digest IS DISTINCT FROM NEW.authority_digest
        OR authority.claimed_at_ms IS DISTINCT FROM NEW.authority_claimed_at_ms
        OR authority.expires_at_ms IS DISTINCT FROM NEW.authority_expires_at_ms
        OR authority.claimed_at_ms > database_now
        OR authority.state IS DISTINCT FROM (
            CASE WHEN NEW.authority_kind = 'preparation'
                 THEN 'preparing' ELSE 'activating' END
        )
        OR (NOT internal_poison AND (
            authority.origin_selection_id IS DISTINCT FROM NEW.selection_id
            OR authority.owner_id IS DISTINCT FROM NEW.selection_owner_id))
    THEN
        RAISE EXCEPTION 'activation quarantine lacks exact unsuperseded authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_authority_exact';
    END IF;
    NEW.quarantined_at_ms := database_now;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_validate_materialization_real_claim_quarantine()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT;
    receipt workflow_plan_v2_materialization_work_selections%ROWTYPE;
    existing_quarantine workflow_plan_v2_materialization_work_quarantines%ROWTYPE;
    authority RECORD;
    internal_poison BOOLEAN := FALSE;
BEGIN
    SELECT * INTO receipt
    FROM workflow_plan_v2_materialization_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    PERFORM 1
    FROM workflow_plan_v2_work_selection_replay_horizons
    WHERE queue_name = 'materialization'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'materialization quarantine replay horizon is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_horizon_required';
    END IF;
    SELECT * INTO existing_quarantine
    FROM workflow_plan_v2_materialization_work_quarantines
    WHERE instance_id = NEW.instance_id
    FOR UPDATE;
    IF existing_quarantine.instance_id IS NOT NULL THEN
        RAISE EXCEPTION 'materialization quarantine already has immutable evidence'
            USING ERRCODE = 'unique_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_already_exists';
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
    );

    SELECT repository.tenant_id, instance.run_id, instance.invocation_id,
           instance.logical_job_id, claim.origin_selection_id,
           claim.owner_id, claim.generation,
           claim.descriptor_digest AS digest, claim.claimed_at_ms,
           claim.expires_at_ms, claim.state
      INTO authority
    FROM workflow_plan_v2_materialization_claims AS claim
    JOIN workflow_plan_v2_instances AS instance ON instance.id = claim.instance_id
    JOIN workflow_runs AS run ON run.id = instance.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    WHERE claim.instance_id = NEW.instance_id
    FOR UPDATE OF claim, instance;

    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    internal_poison := NEW.failure_kind = 'generation_exhausted'
        AND receipt.outcome = 'selecting';
    IF receipt.selection_id IS NULL
        OR receipt.owner_id IS DISTINCT FROM NEW.selection_owner_id
        OR receipt.requested_at_ms IS DISTINCT FROM NEW.selection_requested_at_ms
        OR receipt.duration_ms IS DISTINCT FROM NEW.selection_duration_ms
    THEN
        RAISE EXCEPTION 'materialization quarantine lacks its exact selection request'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_selection_request_exact';
    END IF;
    IF internal_poison THEN
        IF receipt.claimed_at_ms IS NOT NULL OR receipt.expires_at_ms IS NOT NULL
            OR receipt.tenant_id IS NOT NULL OR receipt.run_id IS NOT NULL
            OR receipt.invocation_id IS NOT NULL OR receipt.logical_job_id IS NOT NULL
            OR receipt.instance_id IS NOT NULL OR receipt.generation IS NOT NULL
            OR receipt.authority_digest IS NOT NULL
            OR NEW.selection_generation <> NEW.authority_generation
            OR NEW.selection_claimed_at_ms > database_now
            OR database_now - NEW.selection_claimed_at_ms > 60000
            OR NEW.selection_expires_at_ms - database_now < 1000
            OR NEW.authority_generation <> 9223372036854775807
            OR NEW.authority_expires_at_ms > database_now
        THEN
            RAISE EXCEPTION 'materialization generation poison is not an exact provisional capture'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_quarantine_generation_poison_exact';
        END IF;
    ELSIF NEW.failure_kind = 'generation_exhausted'
        OR receipt.outcome <> 'claimed'
        OR receipt.claimed_at_ms IS DISTINCT FROM NEW.selection_claimed_at_ms
        OR receipt.expires_at_ms IS DISTINCT FROM NEW.selection_expires_at_ms
        OR receipt.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR receipt.run_id IS DISTINCT FROM NEW.run_id
        OR receipt.invocation_id IS DISTINCT FROM NEW.invocation_id
        OR receipt.logical_job_id IS DISTINCT FROM NEW.logical_job_id
        OR receipt.instance_id IS DISTINCT FROM NEW.instance_id
        OR receipt.generation IS DISTINCT FROM NEW.selection_generation
        OR receipt.authority_digest IS DISTINCT FROM NEW.authority_digest
    THEN
        RAISE EXCEPTION 'materialization quarantine lacks the exact claimed receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_selection_exact';
    END IF;

    IF authority IS NULL
        OR (authority.tenant_id, authority.run_id, authority.invocation_id,
            authority.logical_job_id)
           IS DISTINCT FROM
           (NEW.tenant_id, NEW.run_id, NEW.invocation_id, NEW.logical_job_id)
        OR authority.owner_id IS DISTINCT FROM NEW.authority_owner_id
        OR authority.generation IS DISTINCT FROM NEW.authority_generation
        OR authority.generation < NEW.selection_generation
        OR authority.digest IS DISTINCT FROM NEW.authority_digest
        OR authority.claimed_at_ms IS DISTINCT FROM NEW.authority_claimed_at_ms
        OR authority.expires_at_ms IS DISTINCT FROM NEW.authority_expires_at_ms
        OR authority.claimed_at_ms > database_now
        OR authority.state IS DISTINCT FROM 'materializing'
        OR (NOT internal_poison AND (
            authority.origin_selection_id IS DISTINCT FROM NEW.selection_id
            OR authority.owner_id IS DISTINCT FROM NEW.selection_owner_id))
    THEN
        RAISE EXCEPTION 'materialization quarantine lacks exact unsuperseded authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_authority_exact';
    END IF;
    NEW.quarantined_at_ms := database_now;
    RETURN NEW;
END;
$automata$;


-- Origin, generation, and database-issued time form one indivisible real
-- claim transition. Same-origin +1 is a live renewal; a new non-null origin
-- may replace a different origin or a legacy NULL only on an expired +1
-- takeover. Terminal transitions keep the final immutable origin/generation
-- unchanged.
CREATE FUNCTION automata_enforce_preparation_claim_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    claim_duration BIGINT;
    is_takeover BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        claim_duration := NEW.expires_at_ms - NEW.claimed_at_ms;
        IF NEW.state <> 'preparing'
            OR NEW.origin_selection_id IS NULL
            OR NEW.generation <> 1
            OR NEW.claimed_at_ms > database_now
            OR database_now - NEW.claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
        THEN
            RAISE EXCEPTION 'initial preparation authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
        );
        RETURN NEW;
    END IF;

    IF OLD.state = 'preparing' AND NEW.state = 'preparing' THEN
        claim_duration := NEW.expires_at_ms - NEW.claimed_at_ms;
        is_takeover :=
            NEW.origin_selection_id IS DISTINCT FROM OLD.origin_selection_id;
        IF NEW.generation <> OLD.generation + 1
            OR NEW.origin_selection_id IS NULL
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
            OR (NOT is_takeover
                AND NEW.owner_id IS DISTINCT FROM OLD.owner_id)
            OR (is_takeover AND NEW.claimed_at_ms < OLD.expires_at_ms)
            OR (NOT is_takeover AND NEW.claimed_at_ms >= OLD.expires_at_ms)
            OR (NOT is_takeover AND database_now >= OLD.expires_at_ms)
            OR NEW.claimed_at_ms > database_now
            OR database_now - NEW.claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
            OR NEW.expires_at_ms <= OLD.expires_at_ms
        THEN
            RAISE EXCEPTION 'preparation authority successor is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
        );
    ELSIF OLD.state = 'preparing' AND NEW.state = 'prepared' THEN
        IF (NEW.owner_id, NEW.generation, NEW.claimed_at_ms, NEW.expires_at_ms,
            NEW.origin_selection_id, NEW.descriptor_digest)
           IS DISTINCT FROM
           (OLD.owner_id, OLD.generation, OLD.claimed_at_ms, OLD.expires_at_ms,
            OLD.origin_selection_id, OLD.descriptor_digest)
            OR database_now < OLD.claimed_at_ms
            OR database_now >= OLD.expires_at_ms
        THEN
            RAISE EXCEPTION 'preparation terminal authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
        );
    ELSIF (NEW.owner_id, NEW.generation, NEW.claimed_at_ms, NEW.expires_at_ms,
           NEW.origin_selection_id)
          IS DISTINCT FROM
          (OLD.owner_id, OLD.generation, OLD.claimed_at_ms, OLD.expires_at_ms,
           OLD.origin_selection_id)
    THEN
        RAISE EXCEPTION 'preparation retained authority is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_claim_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_enforce_activation_claim_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    claim_duration BIGINT;
    is_takeover BOOLEAN;
BEGIN
    IF OLD.state = 'pending' AND NEW.state = 'activating' THEN
        claim_duration :=
            NEW.activation_expires_at_ms - NEW.activation_claimed_at_ms;
        IF NEW.activation_origin_selection_id IS NULL
            OR NEW.activation_fence <> OLD.activation_fence + 1
            OR NEW.activation_claimed_at_ms > database_now
            OR database_now - NEW.activation_claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
        THEN
            RAISE EXCEPTION 'initial activation authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.id, NULL
        );
    ELSIF OLD.state = 'activating' AND NEW.state = 'activating' THEN
        claim_duration :=
            NEW.activation_expires_at_ms - NEW.activation_claimed_at_ms;
        is_takeover := NEW.activation_origin_selection_id IS DISTINCT FROM
                       OLD.activation_origin_selection_id;
        IF NEW.activation_fence <> OLD.activation_fence + 1
            OR NEW.activation_origin_selection_id IS NULL
            OR NEW.updated_at_ms <> NEW.activation_claimed_at_ms
            OR (NOT is_takeover AND NEW.activation_owner_id IS DISTINCT FROM
                OLD.activation_owner_id)
            OR (is_takeover AND NEW.activation_claimed_at_ms <
                OLD.activation_expires_at_ms)
            OR (NOT is_takeover AND NEW.activation_claimed_at_ms >=
                OLD.activation_expires_at_ms)
            OR (NOT is_takeover
                AND database_now >= OLD.activation_expires_at_ms)
            OR NEW.activation_claimed_at_ms > database_now
            OR database_now - NEW.activation_claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
            OR NEW.activation_expires_at_ms <= OLD.activation_expires_at_ms
            OR NEW.activation_input_digest IS DISTINCT FROM
               OLD.activation_input_digest
        THEN
            RAISE EXCEPTION 'activation authority successor is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.id, NULL
        );
    ELSIF OLD.state = 'activating'
        AND NEW.state IN ('activated', 'skipped')
    THEN
        IF NEW.activation_fence <> OLD.activation_fence
            OR NEW.activation_origin_selection_id IS DISTINCT FROM
               OLD.activation_origin_selection_id
            OR NEW.activation_input_digest IS DISTINCT FROM
               OLD.activation_input_digest
            OR NEW.activation_owner_id IS NOT NULL
            OR NEW.activation_claimed_at_ms IS NOT NULL
            OR NEW.activation_expires_at_ms IS NOT NULL
            OR database_now < OLD.activation_claimed_at_ms
            OR database_now >= OLD.activation_expires_at_ms
        THEN
            RAISE EXCEPTION 'activation terminal authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.id, NULL
        );
    ELSIF (NEW.activation_fence, NEW.activation_owner_id,
           NEW.activation_claimed_at_ms, NEW.activation_expires_at_ms,
           NEW.activation_input_digest, NEW.activation_origin_selection_id)
          IS DISTINCT FROM
          (OLD.activation_fence, OLD.activation_owner_id,
           OLD.activation_claimed_at_ms, OLD.activation_expires_at_ms,
           OLD.activation_input_digest, OLD.activation_origin_selection_id)
    THEN
        RAISE EXCEPTION 'activation retained authority is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_claim_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_enforce_materialization_claim_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    claim_duration BIGINT;
    is_takeover BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        claim_duration := NEW.expires_at_ms - NEW.claimed_at_ms;
        IF NEW.state <> 'materializing'
            OR NEW.origin_selection_id IS NULL
            OR NEW.generation <> 1
            OR NEW.claimed_at_ms > database_now
            OR database_now - NEW.claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
        THEN
            RAISE EXCEPTION 'initial materialization authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
        );
        RETURN NEW;
    END IF;

    IF OLD.state = 'materializing' AND NEW.state = 'materializing' THEN
        claim_duration := NEW.expires_at_ms - NEW.claimed_at_ms;
        is_takeover :=
            NEW.origin_selection_id IS DISTINCT FROM OLD.origin_selection_id;
        IF NEW.generation <> OLD.generation + 1
            OR NEW.origin_selection_id IS NULL
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
            OR (NOT is_takeover
                AND NEW.owner_id IS DISTINCT FROM OLD.owner_id)
            OR (is_takeover AND NEW.claimed_at_ms < OLD.expires_at_ms)
            OR (NOT is_takeover AND NEW.claimed_at_ms >= OLD.expires_at_ms)
            OR (NOT is_takeover AND database_now >= OLD.expires_at_ms)
            OR NEW.claimed_at_ms > database_now
            OR database_now - NEW.claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
            OR NEW.expires_at_ms <= OLD.expires_at_ms
        THEN
            RAISE EXCEPTION 'materialization authority successor is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
        );
    ELSIF OLD.state = 'materializing' AND NEW.state = 'materialized' THEN
        IF (NEW.owner_id, NEW.generation, NEW.claimed_at_ms, NEW.expires_at_ms,
            NEW.origin_selection_id, NEW.descriptor_digest)
           IS DISTINCT FROM
           (OLD.owner_id, OLD.generation, OLD.claimed_at_ms, OLD.expires_at_ms,
            OLD.origin_selection_id, OLD.descriptor_digest)
            OR database_now < OLD.claimed_at_ms
            OR database_now >= OLD.expires_at_ms
        THEN
            RAISE EXCEPTION 'materialization terminal authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
        );
    ELSIF (NEW.owner_id, NEW.generation, NEW.claimed_at_ms, NEW.expires_at_ms,
           NEW.origin_selection_id)
          IS DISTINCT FROM
          (OLD.owner_id, OLD.generation, OLD.claimed_at_ms, OLD.expires_at_ms,
           OLD.origin_selection_id)
    THEN
        RAISE EXCEPTION 'materialization retained authority is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_claim_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_preparation_claims_02_transition
BEFORE INSERT OR UPDATE ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW EXECUTE FUNCTION automata_enforce_preparation_claim_transition();

CREATE TRIGGER workflow_plan_v2_jobs_02_activation_transition
BEFORE UPDATE ON workflow_plan_v2_jobs
FOR EACH ROW EXECUTE FUNCTION automata_enforce_activation_claim_transition();

CREATE TRIGGER workflow_plan_v2_materialization_claims_02_transition
BEFORE INSERT OR UPDATE ON workflow_plan_v2_materialization_claims
FOR EACH ROW EXECUTE FUNCTION automata_enforce_materialization_claim_transition();

CREATE FUNCTION automata_require_active_unquarantined_phase_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
    );
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_preparations_01_active_unquarantined
BEFORE INSERT ON workflow_plan_v2_activation_preparations
FOR EACH ROW EXECUTE FUNCTION automata_require_active_unquarantined_phase_insert();
CREATE TRIGGER workflow_plan_v2_publications_01_active_unquarantined
BEFORE INSERT ON workflow_plan_v2_activation_publications
FOR EACH ROW EXECUTE FUNCTION automata_require_active_unquarantined_phase_insert();
CREATE TRIGGER workflow_plan_v2_instances_01_active_unquarantined
BEFORE INSERT ON workflow_plan_v2_instances
FOR EACH ROW EXECUTE FUNCTION automata_require_active_unquarantined_phase_insert();

CREATE FUNCTION automata_require_activation_publication_state_closure()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    closed BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
    );
    SELECT job.activation_fence = NEW.activation_generation
           AND job.activation_input_digest = NEW.activation_input_digest
           AND job.runtime_policy_revision = NEW.runtime_policy_revision
           AND job.runtime_policy_digest = NEW.runtime_policy_digest
           AND ((NEW.condition_matched AND job.state IN
                    ('activated', 'completed', 'failed', 'cancelled'))
                OR (NOT NEW.condition_matched AND job.state = 'skipped'))
      INTO closed
    FROM workflow_plan_v2_jobs AS job
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
    FOR UPDATE OF job;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF closed IS DISTINCT FROM TRUE
        OR database_now < NEW.activation_claimed_at_ms
        OR database_now >= NEW.activation_expires_at_ms
    THEN
        RAISE EXCEPTION 'activation publication and terminal job state are not closed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_publication_state_closure';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_publication_job_state_closure
AFTER INSERT ON workflow_plan_v2_activation_publications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_activation_publication_state_closure();

-- Migration 0021 knew only expired takeovers. Preserve its concrete-evidence
-- terminal check while admitting exact same-origin live +1 renewal and an
-- expired different- or legacy-NULL-origin takeover.
CREATE OR REPLACE FUNCTION automata_enforce_workflow_plan_v2_materialization_claim_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.instance_id IS DISTINCT FROM OLD.instance_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.expected_job_id IS DISTINCT FROM OLD.expected_job_id
        OR NEW.expected_attempt_id IS DISTINCT FROM OLD.expected_attempt_id
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 materialization claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'materializing' AND NEW.state = 'materializing' THEN
        IF NEW.generation <> OLD.generation + 1
            OR NEW.expires_at_ms <= NEW.claimed_at_ms
            OR NEW.expires_at_ms - NEW.claimed_at_ms > 900000
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
            OR NOT (
                (NEW.origin_selection_id IS NOT DISTINCT FROM OLD.origin_selection_id
                 AND NEW.owner_id IS NOT DISTINCT FROM OLD.owner_id
                 AND NEW.claimed_at_ms >= OLD.claimed_at_ms
                 AND NEW.claimed_at_ms < OLD.expires_at_ms
                 AND NEW.expires_at_ms > OLD.expires_at_ms)
                OR
                (NEW.origin_selection_id IS DISTINCT FROM OLD.origin_selection_id
                 AND NEW.origin_selection_id IS NOT NULL
                 AND NEW.claimed_at_ms >= OLD.expires_at_ms)
            )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 materialization successor is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'materializing' AND NEW.state = 'materialized' THEN
        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NEW.origin_selection_id IS DISTINCT FROM OLD.origin_selection_id
            OR NOT EXISTS (
                SELECT 1
                FROM workflow_plan_v2_concrete_jobs AS concrete
                WHERE concrete.instance_id = NEW.instance_id
                  AND concrete.run_id = NEW.run_id
                  AND concrete.invocation_id = NEW.invocation_id
                  AND concrete.logical_job_id = NEW.logical_job_id
                  AND concrete.descriptor_digest = NEW.descriptor_digest
                  AND concrete.job_id = NEW.expected_job_id
                  AND concrete.initial_attempt_id = NEW.expected_attempt_id
                  AND concrete.claim_owner_id = OLD.owner_id
                  AND concrete.claim_generation = OLD.generation
                  AND concrete.claim_started_at_ms = OLD.claimed_at_ms
                  AND concrete.claim_expires_at_ms = OLD.expires_at_ms
                  AND concrete.committed_at_ms = NEW.updated_at_ms
            )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 materialization transition lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'WorkflowPlan-v2 materialization claim transition is invalid'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE FUNCTION automata_validate_activation_real_claim_renewal_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    selection workflow_plan_v2_activation_work_selections%ROWTYPE;
    authority RECORD;
    database_now BIGINT;
    receipt_count BIGINT;
    predecessor_exact BOOLEAN := FALSE;
BEGIN
    SELECT * INTO selection
    FROM workflow_plan_v2_activation_work_selections
    WHERE selection_id = NEW.selection_id;
    SELECT count(*) INTO receipt_count
    FROM workflow_plan_v2_activation_renewal_receipts
    WHERE selection_id = NEW.selection_id;
    IF NEW.authority_kind = 'preparation' THEN
        SELECT claim.state, claim.origin_selection_id, claim.owner_id,
               claim.generation, claim.claimed_at_ms, claim.expires_at_ms,
               claim.descriptor_digest AS authority_digest,
               claim.runtime_policy_revision, claim.runtime_policy_digest
          INTO authority
        FROM workflow_plan_v2_activation_preparation_claims AS claim
        WHERE claim.logical_job_id = NEW.logical_job_id
        FOR UPDATE;
    ELSE
        SELECT job.state, job.activation_origin_selection_id AS origin_selection_id,
               job.activation_owner_id AS owner_id,
               job.activation_fence AS generation,
               job.activation_claimed_at_ms AS claimed_at_ms,
               job.activation_expires_at_ms AS expires_at_ms,
               job.activation_input_digest AS authority_digest,
               job.runtime_policy_revision, job.runtime_policy_digest
          INTO authority
        FROM workflow_plan_v2_jobs AS job
        WHERE job.id = NEW.logical_job_id
        FOR UPDATE;
    END IF;
    IF selection.selection_id IS NULL OR selection.outcome <> 'claimed'
        OR selection.authority_kind IS DISTINCT FROM NEW.authority_kind
        OR (selection.tenant_id, selection.run_id, selection.invocation_id,
            selection.logical_job_id, selection.owner_id,
            selection.authority_digest)
           IS DISTINCT FROM
           (NEW.tenant_id, NEW.run_id, NEW.invocation_id,
            NEW.logical_job_id, NEW.owner_id, NEW.authority_digest)
    THEN
        RAISE EXCEPTION 'activation renewal lacks its exact selection origin'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_renewal_selection_exact';
    END IF;
    IF NEW.predecessor_generation = selection.generation THEN
        predecessor_exact :=
            (NEW.predecessor_claimed_at_ms, NEW.predecessor_expires_at_ms,
             NEW.owner_id, NEW.authority_digest)
            IS NOT DISTINCT FROM
            (selection.claimed_at_ms, selection.expires_at_ms,
             selection.owner_id, selection.authority_digest);
    ELSE
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_renewal_receipts AS prior
            WHERE prior.selection_id = NEW.selection_id
              AND prior.logical_job_id = NEW.logical_job_id
              AND prior.authority_kind = NEW.authority_kind
              AND prior.successor_generation = NEW.predecessor_generation
              AND prior.successor_claimed_at_ms = NEW.predecessor_claimed_at_ms
              AND prior.successor_expires_at_ms = NEW.predecessor_expires_at_ms
              AND prior.owner_id = NEW.owner_id
              AND prior.runtime_policy_revision = NEW.runtime_policy_revision
              AND prior.runtime_policy_digest = NEW.runtime_policy_digest
              AND prior.authority_digest = NEW.authority_digest
        ) INTO predecessor_exact;
    END IF;
    IF predecessor_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'activation renewal does not extend its exact predecessor chain'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_renewal_predecessor_exact';
    END IF;
    IF receipt_count >= 64 THEN
        RAISE EXCEPTION 'activation selection renewal history is full'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_renewal_history_bounded';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF authority IS NULL
        OR authority.state IS DISTINCT FROM (
            CASE WHEN NEW.authority_kind = 'preparation'
                 THEN 'preparing' ELSE 'activating' END
        )
        OR authority.origin_selection_id IS DISTINCT FROM NEW.selection_id
        OR authority.owner_id IS DISTINCT FROM NEW.owner_id
        OR authority.generation IS DISTINCT FROM NEW.successor_generation
        OR authority.claimed_at_ms IS DISTINCT FROM NEW.successor_claimed_at_ms
        OR authority.expires_at_ms IS DISTINCT FROM NEW.successor_expires_at_ms
        OR authority.authority_digest IS DISTINCT FROM NEW.authority_digest
        OR (authority.runtime_policy_revision, authority.runtime_policy_digest)
           IS DISTINCT FROM
           (NEW.runtime_policy_revision, NEW.runtime_policy_digest)
        OR NEW.successor_expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'activation renewal lacks the exact live successor authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_renewal_successor_exact';
    END IF;
    NEW.validated_at_ms := database_now;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_validate_materialization_real_claim_renewal_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    selection workflow_plan_v2_materialization_work_selections%ROWTYPE;
    authority RECORD;
    database_now BIGINT;
    receipt_count BIGINT;
    predecessor_exact BOOLEAN := FALSE;
BEGIN
    SELECT * INTO selection
    FROM workflow_plan_v2_materialization_work_selections
    WHERE selection_id = NEW.selection_id;
    SELECT count(*) INTO receipt_count
    FROM workflow_plan_v2_materialization_renewal_receipts
    WHERE selection_id = NEW.selection_id;
    SELECT claim.state, claim.origin_selection_id, claim.owner_id,
           claim.generation, claim.claimed_at_ms, claim.expires_at_ms,
           claim.descriptor_digest AS authority_digest,
           claim.runtime_policy_revision, claim.runtime_policy_digest,
           claim.expected_job_id, claim.expected_attempt_id
      INTO authority
    FROM workflow_plan_v2_materialization_claims AS claim
    WHERE claim.instance_id = NEW.instance_id
    FOR UPDATE;
    IF selection.selection_id IS NULL OR selection.outcome <> 'claimed'
        OR (selection.tenant_id, selection.run_id, selection.invocation_id,
            selection.logical_job_id, selection.instance_id,
            selection.owner_id, selection.authority_digest)
           IS DISTINCT FROM
           (NEW.tenant_id, NEW.run_id, NEW.invocation_id,
            NEW.logical_job_id, NEW.instance_id,
            NEW.owner_id, NEW.authority_digest)
        OR (authority.expected_job_id, authority.expected_attempt_id)
           IS DISTINCT FROM (NEW.expected_job_id, NEW.expected_attempt_id)
    THEN
        RAISE EXCEPTION 'materialization renewal lacks its exact selection origin'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_renewal_selection_exact';
    END IF;
    IF NEW.predecessor_generation = selection.generation THEN
        predecessor_exact :=
            (NEW.predecessor_claimed_at_ms, NEW.predecessor_expires_at_ms,
             NEW.owner_id, NEW.authority_digest)
            IS NOT DISTINCT FROM
            (selection.claimed_at_ms, selection.expires_at_ms,
             selection.owner_id, selection.authority_digest);
    ELSE
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_materialization_renewal_receipts AS prior
            WHERE prior.selection_id = NEW.selection_id
              AND prior.instance_id = NEW.instance_id
              AND prior.successor_generation = NEW.predecessor_generation
              AND prior.successor_claimed_at_ms = NEW.predecessor_claimed_at_ms
              AND prior.successor_expires_at_ms = NEW.predecessor_expires_at_ms
              AND prior.owner_id = NEW.owner_id
              AND prior.runtime_policy_revision = NEW.runtime_policy_revision
              AND prior.runtime_policy_digest = NEW.runtime_policy_digest
              AND prior.authority_digest = NEW.authority_digest
              AND prior.expected_job_id = NEW.expected_job_id
              AND prior.expected_attempt_id = NEW.expected_attempt_id
        ) INTO predecessor_exact;
    END IF;
    IF predecessor_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'materialization renewal does not extend its exact predecessor chain'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_renewal_predecessor_exact';
    END IF;
    IF receipt_count >= 64 THEN
        RAISE EXCEPTION 'materialization selection renewal history is full'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_renewal_history_bounded';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF authority IS NULL OR authority.state IS DISTINCT FROM 'materializing'
        OR authority.origin_selection_id IS DISTINCT FROM NEW.selection_id
        OR authority.owner_id IS DISTINCT FROM NEW.owner_id
        OR authority.generation IS DISTINCT FROM NEW.successor_generation
        OR authority.claimed_at_ms IS DISTINCT FROM NEW.successor_claimed_at_ms
        OR authority.expires_at_ms IS DISTINCT FROM NEW.successor_expires_at_ms
        OR authority.authority_digest IS DISTINCT FROM NEW.authority_digest
        OR (authority.runtime_policy_revision, authority.runtime_policy_digest)
           IS DISTINCT FROM
           (NEW.runtime_policy_revision, NEW.runtime_policy_digest)
        OR (authority.expected_job_id, authority.expected_attempt_id)
           IS DISTINCT FROM (NEW.expected_job_id, NEW.expected_attempt_id)
        OR NEW.successor_expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'materialization renewal lacks the exact live successor authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_renewal_successor_exact';
    END IF;
    NEW.validated_at_ms := database_now;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_renewal_receipt_validate
BEFORE INSERT ON workflow_plan_v2_activation_renewal_receipts
FOR EACH ROW EXECUTE FUNCTION automata_validate_activation_real_claim_renewal_receipt();
CREATE TRIGGER workflow_plan_v2_materialization_renewal_receipt_validate
BEFORE INSERT ON workflow_plan_v2_materialization_renewal_receipts
FOR EACH ROW EXECUTE FUNCTION automata_validate_materialization_real_claim_renewal_receipt();

CREATE TRIGGER workflow_plan_v2_activation_renewal_receipt_reject_update
BEFORE UPDATE ON workflow_plan_v2_activation_renewal_receipts
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_materialization_renewal_receipt_reject_update
BEFORE UPDATE ON workflow_plan_v2_materialization_renewal_receipts
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_activation_renewal_receipt_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_activation_renewal_receipts
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();
CREATE TRIGGER workflow_plan_v2_materialization_renewal_receipt_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_materialization_renewal_receipts
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE FUNCTION automata_require_renewal_receipt_parent_deleted()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    parent_exists BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'workflow_plan_v2_activation_renewal_receipts' THEN
        SELECT EXISTS (
            SELECT 1 FROM workflow_plan_v2_activation_work_selections
            WHERE selection_id = OLD.selection_id
        ) INTO parent_exists;
    ELSE
        SELECT EXISTS (
            SELECT 1 FROM workflow_plan_v2_materialization_work_selections
            WHERE selection_id = OLD.selection_id
        ) INTO parent_exists;
    END IF;
    IF parent_exists THEN
        RAISE EXCEPTION 'renewal evidence is retained with its selection receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_real_claim_renewal_receipt_retained';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_activation_renewal_receipt_delete_guard
AFTER DELETE ON workflow_plan_v2_activation_renewal_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_renewal_receipt_parent_deleted();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_materialization_renewal_receipt_delete_guard
AFTER DELETE ON workflow_plan_v2_materialization_renewal_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_renewal_receipt_parent_deleted();

-- The reciprocal side of renewal custody: every currently active authority is
-- either the exact selected fence or the exact successor in the immutable
-- receipt chain.  A direct claim UPDATE without its receipt cannot commit.
CREATE FUNCTION automata_require_final_activation_work_selection()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    receipt workflow_plan_v2_activation_work_selections%ROWTYPE;
    authority RECORD;
    exact_evidence BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    SELECT * INTO receipt
    FROM workflow_plan_v2_activation_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF receipt.selection_id IS NULL OR receipt.outcome = 'selecting'
        OR receipt.expires_at_ms IS NULL
    THEN
        RAISE EXCEPTION 'activation selection may not commit without a live handoff budget'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_must_finalize_live';
    END IF;
    IF receipt.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_work_quarantines AS quarantine
            WHERE quarantine.selection_id = receipt.selection_id
              AND quarantine.logical_job_id = receipt.logical_job_id
              AND quarantine.tenant_id = receipt.tenant_id
              AND quarantine.run_id = receipt.run_id
              AND quarantine.invocation_id = receipt.invocation_id
              AND quarantine.selection_owner_id = receipt.owner_id
              AND quarantine.selection_requested_at_ms = receipt.requested_at_ms
              AND quarantine.selection_duration_ms = receipt.duration_ms
              AND quarantine.selection_generation = receipt.generation
              AND quarantine.selection_claimed_at_ms = receipt.claimed_at_ms
              AND quarantine.selection_expires_at_ms = receipt.expires_at_ms
              AND quarantine.authority_kind = receipt.authority_kind
              AND quarantine.authority_digest = receipt.authority_digest
        ) INTO exact_evidence;
    ELSIF receipt.expires_at_ms - database_now < 1000 THEN
        RAISE EXCEPTION 'activation selection may not commit without a live handoff budget'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_must_finalize_live';
    ELSIF receipt.outcome IN ('idle', 'contended') THEN
        RETURN NULL;
    ELSIF receipt.authority_kind = 'preparation' THEN
        SELECT claim.state, claim.origin_selection_id, claim.owner_id,
               claim.generation, claim.descriptor_digest AS authority_digest,
               claim.claimed_at_ms, claim.expires_at_ms,
               claim.runtime_policy_revision, claim.runtime_policy_digest
          INTO authority
        FROM workflow_plan_v2_activation_preparation_claims AS claim
        WHERE claim.logical_job_id = receipt.logical_job_id
        FOR UPDATE;
        exact_evidence := authority IS NOT NULL
            AND authority.state = 'preparing'
            AND authority.origin_selection_id = receipt.selection_id
            AND authority.owner_id = receipt.owner_id
            AND authority.authority_digest = receipt.authority_digest
            AND authority.expires_at_ms - database_now >= 1000
            AND (
                (authority.generation = receipt.generation
                 AND authority.claimed_at_ms = receipt.claimed_at_ms
                 AND authority.expires_at_ms = receipt.expires_at_ms)
                OR EXISTS (
                    SELECT 1
                    FROM workflow_plan_v2_activation_renewal_receipts AS renewal
                    WHERE renewal.selection_id = receipt.selection_id
                      AND renewal.logical_job_id = receipt.logical_job_id
                      AND renewal.authority_kind = 'preparation'
                      AND renewal.successor_generation = authority.generation
                      AND renewal.successor_claimed_at_ms = authority.claimed_at_ms
                      AND renewal.successor_expires_at_ms = authority.expires_at_ms
                      AND renewal.owner_id = authority.owner_id
                      AND renewal.authority_digest = authority.authority_digest
                      AND renewal.runtime_policy_revision = authority.runtime_policy_revision
                      AND renewal.runtime_policy_digest = authority.runtime_policy_digest
                )
            );
    ELSE
        SELECT job.state,
               job.activation_origin_selection_id AS origin_selection_id,
               job.activation_owner_id AS owner_id,
               job.activation_fence AS generation,
               job.activation_input_digest AS authority_digest,
               job.activation_claimed_at_ms AS claimed_at_ms,
               job.activation_expires_at_ms AS expires_at_ms,
               job.runtime_policy_revision, job.runtime_policy_digest
          INTO authority
        FROM workflow_plan_v2_jobs AS job
        WHERE job.id = receipt.logical_job_id
        FOR UPDATE;
        exact_evidence := authority IS NOT NULL
            AND authority.state = 'activating'
            AND authority.origin_selection_id = receipt.selection_id
            AND authority.owner_id = receipt.owner_id
            AND authority.authority_digest = receipt.authority_digest
            AND authority.expires_at_ms - database_now >= 1000
            AND (
                (authority.generation = receipt.generation
                 AND authority.claimed_at_ms = receipt.claimed_at_ms
                 AND authority.expires_at_ms = receipt.expires_at_ms)
                OR EXISTS (
                    SELECT 1
                    FROM workflow_plan_v2_activation_renewal_receipts AS renewal
                    WHERE renewal.selection_id = receipt.selection_id
                      AND renewal.logical_job_id = receipt.logical_job_id
                      AND renewal.authority_kind = 'activation'
                      AND renewal.successor_generation = authority.generation
                      AND renewal.successor_claimed_at_ms = authority.claimed_at_ms
                      AND renewal.successor_expires_at_ms = authority.expires_at_ms
                      AND renewal.owner_id = authority.owner_id
                      AND renewal.authority_digest = authority.authority_digest
                      AND renewal.runtime_policy_revision = authority.runtime_policy_revision
                      AND renewal.runtime_policy_digest = authority.runtime_policy_digest
                )
            );
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'final activation selection lacks exact current durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_final_evidence_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE FUNCTION automata_require_final_materialization_work_selection()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    receipt workflow_plan_v2_materialization_work_selections%ROWTYPE;
    authority RECORD;
    exact_evidence BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    SELECT * INTO receipt
    FROM workflow_plan_v2_materialization_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF receipt.selection_id IS NULL OR receipt.outcome = 'selecting'
        OR receipt.expires_at_ms IS NULL
    THEN
        RAISE EXCEPTION 'materialization selection may not commit without a live handoff budget'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_must_finalize_live';
    END IF;
    IF receipt.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_materialization_work_quarantines AS quarantine
            WHERE quarantine.selection_id = receipt.selection_id
              AND quarantine.instance_id = receipt.instance_id
              AND quarantine.tenant_id = receipt.tenant_id
              AND quarantine.run_id = receipt.run_id
              AND quarantine.invocation_id = receipt.invocation_id
              AND quarantine.logical_job_id = receipt.logical_job_id
              AND quarantine.selection_owner_id = receipt.owner_id
              AND quarantine.selection_requested_at_ms = receipt.requested_at_ms
              AND quarantine.selection_duration_ms = receipt.duration_ms
              AND quarantine.selection_generation = receipt.generation
              AND quarantine.selection_claimed_at_ms = receipt.claimed_at_ms
              AND quarantine.selection_expires_at_ms = receipt.expires_at_ms
              AND quarantine.authority_digest = receipt.authority_digest
        ) INTO exact_evidence;
    ELSIF receipt.expires_at_ms - database_now < 1000 THEN
        RAISE EXCEPTION 'materialization selection may not commit without a live handoff budget'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_must_finalize_live';
    ELSIF receipt.outcome IN ('idle', 'contended') THEN
        RETURN NULL;
    ELSE
        SELECT claim.state, claim.origin_selection_id, claim.owner_id,
               claim.generation, claim.descriptor_digest AS authority_digest,
               claim.claimed_at_ms, claim.expires_at_ms,
               claim.runtime_policy_revision, claim.runtime_policy_digest,
               claim.expected_job_id, claim.expected_attempt_id
          INTO authority
        FROM workflow_plan_v2_materialization_claims AS claim
        WHERE claim.instance_id = receipt.instance_id
        FOR UPDATE;
        exact_evidence := authority IS NOT NULL
            AND authority.state = 'materializing'
            AND authority.origin_selection_id = receipt.selection_id
            AND authority.owner_id = receipt.owner_id
            AND authority.authority_digest = receipt.authority_digest
            AND authority.expires_at_ms - database_now >= 1000
            AND (
                (authority.generation = receipt.generation
                 AND authority.claimed_at_ms = receipt.claimed_at_ms
                 AND authority.expires_at_ms = receipt.expires_at_ms)
                OR EXISTS (
                    SELECT 1
                    FROM workflow_plan_v2_materialization_renewal_receipts AS renewal
                    WHERE renewal.selection_id = receipt.selection_id
                      AND renewal.instance_id = receipt.instance_id
                      AND renewal.successor_generation = authority.generation
                      AND renewal.successor_claimed_at_ms = authority.claimed_at_ms
                      AND renewal.successor_expires_at_ms = authority.expires_at_ms
                      AND renewal.owner_id = authority.owner_id
                      AND renewal.authority_digest = authority.authority_digest
                      AND renewal.runtime_policy_revision = authority.runtime_policy_revision
                      AND renewal.runtime_policy_digest = authority.runtime_policy_digest
                      AND renewal.expected_job_id = authority.expected_job_id
                      AND renewal.expected_attempt_id = authority.expected_attempt_id
                )
            );
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'final materialization selection lacks exact current durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_final_evidence_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

-- Reciprocal quarantine custody is checked at transaction end.  The ordinary
-- quarantine path intentionally leaves its immutable parent receipt claimed;
-- the internal generation-poison path inserts while the parent is selecting
-- and must finalize that exact parent as quarantined before commit.
CREATE FUNCTION automata_require_final_activation_work_quarantine()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    receipt workflow_plan_v2_activation_work_selections%ROWTYPE;
    expected_outcome TEXT;
BEGIN
    SELECT * INTO receipt
    FROM workflow_plan_v2_activation_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    expected_outcome := CASE
        WHEN NEW.failure_kind = 'generation_exhausted' THEN 'quarantined'
        ELSE 'claimed'
    END;
    IF receipt.selection_id IS NULL
        OR receipt.outcome IS DISTINCT FROM expected_outcome
        OR (receipt.owner_id, receipt.requested_at_ms, receipt.duration_ms,
            receipt.claimed_at_ms, receipt.expires_at_ms, receipt.tenant_id,
            receipt.run_id, receipt.invocation_id, receipt.logical_job_id,
            receipt.generation, receipt.authority_kind, receipt.authority_digest)
           IS DISTINCT FROM
           (NEW.selection_owner_id, NEW.selection_requested_at_ms,
            NEW.selection_duration_ms, NEW.selection_claimed_at_ms,
            NEW.selection_expires_at_ms, NEW.tenant_id, NEW.run_id,
            NEW.invocation_id, NEW.logical_job_id, NEW.selection_generation,
            NEW.authority_kind, NEW.authority_digest)
    THEN
        RAISE EXCEPTION 'activation quarantine lacks its exact final selection parent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_parent_final_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE FUNCTION automata_require_final_materialization_work_quarantine()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    receipt workflow_plan_v2_materialization_work_selections%ROWTYPE;
    expected_outcome TEXT;
BEGIN
    SELECT * INTO receipt
    FROM workflow_plan_v2_materialization_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    expected_outcome := CASE
        WHEN NEW.failure_kind = 'generation_exhausted' THEN 'quarantined'
        ELSE 'claimed'
    END;
    IF receipt.selection_id IS NULL
        OR receipt.outcome IS DISTINCT FROM expected_outcome
        OR (receipt.owner_id, receipt.requested_at_ms, receipt.duration_ms,
            receipt.claimed_at_ms, receipt.expires_at_ms, receipt.tenant_id,
            receipt.run_id, receipt.invocation_id, receipt.logical_job_id,
            receipt.instance_id, receipt.generation, receipt.authority_digest)
           IS DISTINCT FROM
           (NEW.selection_owner_id, NEW.selection_requested_at_ms,
            NEW.selection_duration_ms, NEW.selection_claimed_at_ms,
            NEW.selection_expires_at_ms, NEW.tenant_id, NEW.run_id,
            NEW.invocation_id, NEW.logical_job_id, NEW.instance_id,
            NEW.selection_generation, NEW.authority_digest)
    THEN
        RAISE EXCEPTION 'materialization quarantine lacks its exact final selection parent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_parent_final_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

-- Deferred lineage is reciprocal: the real claim must retain either the
-- exact selecting fence that issued it or the exact immutable renewal edge.
-- The final active tuple is re-read under graph/quarantine custody and must
-- still have a commit-current handoff budget.
CREATE FUNCTION automata_require_preparation_claim_lineage()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_claim workflow_plan_v2_activation_preparation_claims%ROWTYPE;
    current_state TEXT;
    event_exact BOOLEAN := FALSE;
    current_exact BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    IF NEW.state = 'preparing' THEN
        SELECT (
            EXISTS (
                SELECT 1
                FROM workflow_plan_v2_activation_work_selections AS selection
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE selection.selection_id = NEW.origin_selection_id
                  AND selection.outcome = 'claimed'
                  AND selection.authority_kind = 'preparation'
                  AND selection.tenant_id = repository.tenant_id
                  AND selection.run_id = NEW.run_id
                  AND selection.invocation_id = NEW.invocation_id
                  AND selection.logical_job_id = NEW.logical_job_id
                  AND selection.owner_id = NEW.owner_id
                  AND selection.generation = NEW.generation
                  AND selection.claimed_at_ms = NEW.claimed_at_ms
                  AND selection.expires_at_ms = NEW.expires_at_ms
                  AND selection.authority_digest = NEW.descriptor_digest
            ) OR EXISTS (
                SELECT 1
                FROM workflow_plan_v2_activation_renewal_receipts AS renewal
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE renewal.selection_id = NEW.origin_selection_id
                  AND renewal.authority_kind = 'preparation'
                  AND renewal.tenant_id = repository.tenant_id
                  AND renewal.run_id = NEW.run_id
                  AND renewal.invocation_id = NEW.invocation_id
                  AND renewal.logical_job_id = NEW.logical_job_id
                  AND renewal.owner_id = NEW.owner_id
                  AND renewal.successor_generation = NEW.generation
                  AND renewal.successor_claimed_at_ms = NEW.claimed_at_ms
                  AND renewal.successor_expires_at_ms = NEW.expires_at_ms
                  AND renewal.authority_digest = NEW.descriptor_digest
                  AND renewal.runtime_policy_revision =
                      NEW.runtime_policy_revision
                  AND renewal.runtime_policy_digest = NEW.runtime_policy_digest
            )
        ) INTO event_exact;
        IF event_exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'preparation claim event lacks exact selection lineage'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_claim_lineage_exact';
        END IF;
    END IF;

    SELECT state INTO current_state
    FROM workflow_plan_v2_activation_preparation_claims
    WHERE logical_job_id = NEW.logical_job_id;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'preparation claim lineage target disappeared'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_claim_lineage_retained';
    END IF;
    IF current_state <> 'preparing' THEN
        RETURN NULL;
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
    );
    SELECT * INTO current_claim
    FROM workflow_plan_v2_activation_preparation_claims
    WHERE logical_job_id = NEW.logical_job_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT (
        EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_work_selections AS selection
            JOIN workflow_runs AS run ON run.id = current_claim.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE selection.selection_id = current_claim.origin_selection_id
              AND selection.outcome = 'claimed'
              AND selection.authority_kind = 'preparation'
              AND selection.tenant_id = repository.tenant_id
              AND selection.run_id = current_claim.run_id
              AND selection.invocation_id = current_claim.invocation_id
              AND selection.logical_job_id = current_claim.logical_job_id
              AND selection.owner_id = current_claim.owner_id
              AND selection.generation = current_claim.generation
              AND selection.claimed_at_ms = current_claim.claimed_at_ms
              AND selection.expires_at_ms = current_claim.expires_at_ms
              AND selection.authority_digest = current_claim.descriptor_digest
        ) OR EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_renewal_receipts AS renewal
            JOIN workflow_runs AS run ON run.id = current_claim.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE renewal.selection_id = current_claim.origin_selection_id
              AND renewal.authority_kind = 'preparation'
              AND renewal.tenant_id = repository.tenant_id
              AND renewal.run_id = current_claim.run_id
              AND renewal.invocation_id = current_claim.invocation_id
              AND renewal.logical_job_id = current_claim.logical_job_id
              AND renewal.owner_id = current_claim.owner_id
              AND renewal.successor_generation = current_claim.generation
              AND renewal.successor_claimed_at_ms = current_claim.claimed_at_ms
              AND renewal.successor_expires_at_ms = current_claim.expires_at_ms
              AND renewal.authority_digest = current_claim.descriptor_digest
              AND renewal.runtime_policy_revision =
                  current_claim.runtime_policy_revision
              AND renewal.runtime_policy_digest =
                  current_claim.runtime_policy_digest
        )
    ) INTO current_exact;
    IF current_exact IS DISTINCT FROM TRUE
        OR database_now < current_claim.claimed_at_ms
        OR current_claim.expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'active preparation claim lacks live exact lineage'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_claim_lineage_current';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE FUNCTION automata_require_activation_claim_lineage()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_job workflow_plan_v2_jobs%ROWTYPE;
    current_state TEXT;
    event_exact BOOLEAN := FALSE;
    current_exact BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    IF NEW.state = 'activating' THEN
        SELECT (
            EXISTS (
                SELECT 1
                FROM workflow_plan_v2_activation_work_selections AS selection
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE selection.selection_id =
                      NEW.activation_origin_selection_id
                  AND selection.outcome = 'claimed'
                  AND selection.authority_kind = 'activation'
                  AND selection.tenant_id = repository.tenant_id
                  AND selection.run_id = NEW.run_id
                  AND selection.invocation_id = NEW.invocation_id
                  AND selection.logical_job_id = NEW.id
                  AND selection.owner_id = NEW.activation_owner_id
                  AND selection.generation = NEW.activation_fence
                  AND selection.claimed_at_ms = NEW.activation_claimed_at_ms
                  AND selection.expires_at_ms = NEW.activation_expires_at_ms
                  AND selection.authority_digest = NEW.activation_input_digest
            ) OR EXISTS (
                SELECT 1
                FROM workflow_plan_v2_activation_renewal_receipts AS renewal
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE renewal.selection_id =
                      NEW.activation_origin_selection_id
                  AND renewal.authority_kind = 'activation'
                  AND renewal.tenant_id = repository.tenant_id
                  AND renewal.run_id = NEW.run_id
                  AND renewal.invocation_id = NEW.invocation_id
                  AND renewal.logical_job_id = NEW.id
                  AND renewal.owner_id = NEW.activation_owner_id
                  AND renewal.successor_generation = NEW.activation_fence
                  AND renewal.successor_claimed_at_ms =
                      NEW.activation_claimed_at_ms
                  AND renewal.successor_expires_at_ms =
                      NEW.activation_expires_at_ms
                  AND renewal.authority_digest = NEW.activation_input_digest
                  AND renewal.runtime_policy_revision =
                      NEW.runtime_policy_revision
                  AND renewal.runtime_policy_digest = NEW.runtime_policy_digest
            )
        ) INTO event_exact;
        IF event_exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'activation claim event lacks exact selection lineage'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_lineage_exact';
        END IF;
    END IF;

    SELECT state INTO current_state
    FROM workflow_plan_v2_jobs
    WHERE run_id = NEW.run_id
      AND invocation_id = NEW.invocation_id
      AND id = NEW.id;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'activation claim lineage target disappeared'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_claim_lineage_retained';
    END IF;
    IF current_state <> 'activating' THEN
        RETURN NULL;
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.id, NULL
    );
    SELECT * INTO current_job
    FROM workflow_plan_v2_jobs
    WHERE run_id = NEW.run_id
      AND invocation_id = NEW.invocation_id
      AND id = NEW.id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT (
        EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_work_selections AS selection
            JOIN workflow_runs AS run ON run.id = current_job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE selection.selection_id =
                  current_job.activation_origin_selection_id
              AND selection.outcome = 'claimed'
              AND selection.authority_kind = 'activation'
              AND selection.tenant_id = repository.tenant_id
              AND selection.run_id = current_job.run_id
              AND selection.invocation_id = current_job.invocation_id
              AND selection.logical_job_id = current_job.id
              AND selection.owner_id = current_job.activation_owner_id
              AND selection.generation = current_job.activation_fence
              AND selection.claimed_at_ms =
                  current_job.activation_claimed_at_ms
              AND selection.expires_at_ms =
                  current_job.activation_expires_at_ms
              AND selection.authority_digest =
                  current_job.activation_input_digest
        ) OR EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_renewal_receipts AS renewal
            JOIN workflow_runs AS run ON run.id = current_job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE renewal.selection_id =
                  current_job.activation_origin_selection_id
              AND renewal.authority_kind = 'activation'
              AND renewal.tenant_id = repository.tenant_id
              AND renewal.run_id = current_job.run_id
              AND renewal.invocation_id = current_job.invocation_id
              AND renewal.logical_job_id = current_job.id
              AND renewal.owner_id = current_job.activation_owner_id
              AND renewal.successor_generation = current_job.activation_fence
              AND renewal.successor_claimed_at_ms =
                  current_job.activation_claimed_at_ms
              AND renewal.successor_expires_at_ms =
                  current_job.activation_expires_at_ms
              AND renewal.authority_digest =
                  current_job.activation_input_digest
              AND renewal.runtime_policy_revision =
                  current_job.runtime_policy_revision
              AND renewal.runtime_policy_digest =
                  current_job.runtime_policy_digest
        )
    ) INTO current_exact;
    IF current_exact IS DISTINCT FROM TRUE
        OR database_now < current_job.activation_claimed_at_ms
        OR current_job.activation_expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'active activation claim lacks live exact lineage'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_claim_lineage_current';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE FUNCTION automata_require_materialization_claim_lineage()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_claim workflow_plan_v2_materialization_claims%ROWTYPE;
    current_state TEXT;
    event_exact BOOLEAN := FALSE;
    current_exact BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    IF NEW.state = 'materializing' THEN
        SELECT (
            EXISTS (
                SELECT 1
                FROM workflow_plan_v2_materialization_work_selections AS selection
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE selection.selection_id = NEW.origin_selection_id
                  AND selection.outcome = 'claimed'
                  AND selection.tenant_id = repository.tenant_id
                  AND selection.run_id = NEW.run_id
                  AND selection.invocation_id = NEW.invocation_id
                  AND selection.logical_job_id = NEW.logical_job_id
                  AND selection.instance_id = NEW.instance_id
                  AND selection.owner_id = NEW.owner_id
                  AND selection.generation = NEW.generation
                  AND selection.claimed_at_ms = NEW.claimed_at_ms
                  AND selection.expires_at_ms = NEW.expires_at_ms
                  AND selection.authority_digest = NEW.descriptor_digest
            ) OR EXISTS (
                SELECT 1
                FROM workflow_plan_v2_materialization_renewal_receipts AS renewal
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE renewal.selection_id = NEW.origin_selection_id
                  AND renewal.tenant_id = repository.tenant_id
                  AND renewal.run_id = NEW.run_id
                  AND renewal.invocation_id = NEW.invocation_id
                  AND renewal.logical_job_id = NEW.logical_job_id
                  AND renewal.instance_id = NEW.instance_id
                  AND renewal.owner_id = NEW.owner_id
                  AND renewal.successor_generation = NEW.generation
                  AND renewal.successor_claimed_at_ms = NEW.claimed_at_ms
                  AND renewal.successor_expires_at_ms = NEW.expires_at_ms
                  AND renewal.authority_digest = NEW.descriptor_digest
                  AND renewal.runtime_policy_revision =
                      NEW.runtime_policy_revision
                  AND renewal.runtime_policy_digest = NEW.runtime_policy_digest
                  AND renewal.expected_job_id = NEW.expected_job_id
                  AND renewal.expected_attempt_id = NEW.expected_attempt_id
            )
        ) INTO event_exact;
        IF event_exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'materialization claim event lacks exact selection lineage'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_claim_lineage_exact';
        END IF;
    END IF;

    SELECT state INTO current_state
    FROM workflow_plan_v2_materialization_claims
    WHERE instance_id = NEW.instance_id;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'materialization claim lineage target disappeared'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_claim_lineage_retained';
    END IF;
    IF current_state <> 'materializing' THEN
        RETURN NULL;
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
    );
    SELECT * INTO current_claim
    FROM workflow_plan_v2_materialization_claims
    WHERE instance_id = NEW.instance_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT (
        EXISTS (
            SELECT 1
            FROM workflow_plan_v2_materialization_work_selections AS selection
            JOIN workflow_runs AS run ON run.id = current_claim.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE selection.selection_id = current_claim.origin_selection_id
              AND selection.outcome = 'claimed'
              AND selection.tenant_id = repository.tenant_id
              AND selection.run_id = current_claim.run_id
              AND selection.invocation_id = current_claim.invocation_id
              AND selection.logical_job_id = current_claim.logical_job_id
              AND selection.instance_id = current_claim.instance_id
              AND selection.owner_id = current_claim.owner_id
              AND selection.generation = current_claim.generation
              AND selection.claimed_at_ms = current_claim.claimed_at_ms
              AND selection.expires_at_ms = current_claim.expires_at_ms
              AND selection.authority_digest = current_claim.descriptor_digest
        ) OR EXISTS (
            SELECT 1
            FROM workflow_plan_v2_materialization_renewal_receipts AS renewal
            JOIN workflow_runs AS run ON run.id = current_claim.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE renewal.selection_id = current_claim.origin_selection_id
              AND renewal.tenant_id = repository.tenant_id
              AND renewal.run_id = current_claim.run_id
              AND renewal.invocation_id = current_claim.invocation_id
              AND renewal.logical_job_id = current_claim.logical_job_id
              AND renewal.instance_id = current_claim.instance_id
              AND renewal.owner_id = current_claim.owner_id
              AND renewal.successor_generation = current_claim.generation
              AND renewal.successor_claimed_at_ms = current_claim.claimed_at_ms
              AND renewal.successor_expires_at_ms = current_claim.expires_at_ms
              AND renewal.authority_digest = current_claim.descriptor_digest
              AND renewal.runtime_policy_revision =
                  current_claim.runtime_policy_revision
              AND renewal.runtime_policy_digest =
                  current_claim.runtime_policy_digest
              AND renewal.expected_job_id = current_claim.expected_job_id
              AND renewal.expected_attempt_id = current_claim.expected_attempt_id
        )
    ) INTO current_exact;
    IF current_exact IS DISTINCT FROM TRUE
        OR database_now < current_claim.claimed_at_ms
        OR current_claim.expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'active materialization claim lacks live exact lineage'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_claim_lineage_current';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE FUNCTION automata_require_preparation_binding_state_closure()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_claim workflow_plan_v2_activation_preparation_claims%ROWTYPE;
    binding workflow_plan_v2_activation_preparations%ROWTYPE;
    database_now BIGINT;
    closed BOOLEAN := FALSE;
BEGIN
    SELECT * INTO current_claim
    FROM workflow_plan_v2_activation_preparation_claims
    WHERE logical_job_id = NEW.logical_job_id;
    IF current_claim.logical_job_id IS NULL THEN
        RAISE EXCEPTION 'preparation binding closure lost its durable claim'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_binding_claim_retained';
    END IF;
    PERFORM automata_require_active_unquarantined_workflow_phase(
        current_claim.run_id, current_claim.invocation_id,
        current_claim.logical_job_id, NULL
    );
    SELECT * INTO current_claim
    FROM workflow_plan_v2_activation_preparation_claims
    WHERE logical_job_id = NEW.logical_job_id
    FOR UPDATE;
    SELECT * INTO binding
    FROM workflow_plan_v2_activation_preparations
    WHERE logical_job_id = NEW.logical_job_id
    FOR SHARE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;

    IF current_claim.state = 'preparing' THEN
        closed := binding.logical_job_id IS NULL;
    ELSE
        closed := current_claim.state = 'prepared'
            AND binding.logical_job_id IS NOT NULL
            AND binding.run_id = current_claim.run_id
            AND binding.invocation_id = current_claim.invocation_id
            AND binding.descriptor_digest = current_claim.descriptor_digest
            AND binding.claim_owner_id = current_claim.owner_id
            AND binding.claim_generation = current_claim.generation
            AND binding.claim_started_at_ms = current_claim.claimed_at_ms
            AND binding.claim_expires_at_ms = current_claim.expires_at_ms
            AND binding.claim_origin_selection_id =
                current_claim.origin_selection_id
            AND binding.bound_at_ms = current_claim.updated_at_ms
            AND binding.runtime_policy_revision =
                current_claim.runtime_policy_revision
            AND binding.runtime_policy_digest = current_claim.runtime_policy_digest
            AND database_now >= current_claim.claimed_at_ms
            AND database_now < current_claim.expires_at_ms;
    END IF;
    IF closed IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'preparation binding and claim state are not closed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_binding_state_closure';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE FUNCTION automata_require_live_concrete_job_authority()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_claim workflow_plan_v2_materialization_claims%ROWTYPE;
    database_now BIGINT;
BEGIN
    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
    );
    SELECT * INTO current_claim
    FROM workflow_plan_v2_materialization_claims
    WHERE instance_id = NEW.instance_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF current_claim.instance_id IS NULL
        OR current_claim.state <> 'materializing'
        OR current_claim.run_id IS DISTINCT FROM NEW.run_id
        OR current_claim.invocation_id IS DISTINCT FROM NEW.invocation_id
        OR current_claim.logical_job_id IS DISTINCT FROM NEW.logical_job_id
        OR current_claim.descriptor_digest IS DISTINCT FROM NEW.descriptor_digest
        OR current_claim.expected_job_id IS DISTINCT FROM NEW.job_id
        OR current_claim.expected_attempt_id IS DISTINCT FROM
           NEW.initial_attempt_id
        OR current_claim.owner_id IS DISTINCT FROM NEW.claim_owner_id
        OR current_claim.generation IS DISTINCT FROM NEW.claim_generation
        OR current_claim.claimed_at_ms IS DISTINCT FROM NEW.claim_started_at_ms
        OR current_claim.expires_at_ms IS DISTINCT FROM NEW.claim_expires_at_ms
        OR current_claim.runtime_policy_revision IS DISTINCT FROM
           NEW.runtime_policy_revision
        OR current_claim.runtime_policy_digest IS DISTINCT FROM
           NEW.runtime_policy_digest
        OR database_now < current_claim.claimed_at_ms
        OR database_now >= current_claim.expires_at_ms
    THEN
        RAISE EXCEPTION 'concrete job insert lacks live exact materialization authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_concrete_job_live_authority_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_require_materialization_state_closure()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_claim workflow_plan_v2_materialization_claims%ROWTYPE;
    concrete workflow_plan_v2_concrete_jobs%ROWTYPE;
    database_now BIGINT;
    closed BOOLEAN := FALSE;
BEGIN
    SELECT * INTO current_claim
    FROM workflow_plan_v2_materialization_claims
    WHERE instance_id = NEW.instance_id;
    IF current_claim.instance_id IS NULL THEN
        RAISE EXCEPTION 'materialization closure lost its durable claim'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_claim_retained';
    END IF;
    PERFORM automata_require_active_unquarantined_workflow_phase(
        current_claim.run_id, current_claim.invocation_id,
        current_claim.logical_job_id, current_claim.instance_id
    );
    SELECT * INTO current_claim
    FROM workflow_plan_v2_materialization_claims
    WHERE instance_id = NEW.instance_id
    FOR UPDATE;
    SELECT * INTO concrete
    FROM workflow_plan_v2_concrete_jobs
    WHERE instance_id = NEW.instance_id
    FOR SHARE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;

    IF current_claim.state = 'materializing' THEN
        closed := concrete.instance_id IS NULL;
    ELSE
        closed := current_claim.state = 'materialized'
            AND concrete.instance_id IS NOT NULL
            AND concrete.run_id = current_claim.run_id
            AND concrete.invocation_id = current_claim.invocation_id
            AND concrete.logical_job_id = current_claim.logical_job_id
            AND concrete.descriptor_digest = current_claim.descriptor_digest
            AND concrete.job_id = current_claim.expected_job_id
            AND concrete.initial_attempt_id = current_claim.expected_attempt_id
            AND concrete.claim_owner_id = current_claim.owner_id
            AND concrete.claim_generation = current_claim.generation
            AND concrete.claim_started_at_ms = current_claim.claimed_at_ms
            AND concrete.claim_expires_at_ms = current_claim.expires_at_ms
            AND concrete.committed_at_ms = current_claim.updated_at_ms
            AND concrete.runtime_policy_revision =
                current_claim.runtime_policy_revision
            AND concrete.runtime_policy_digest = current_claim.runtime_policy_digest
            AND database_now >= current_claim.claimed_at_ms
            AND database_now < current_claim.expires_at_ms;
    END IF;
    IF closed IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'materialization claim and concrete job are not closed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_state_closure';
    END IF;
    RETURN NULL;
END;
$automata$;

-- Bind every final guard exactly once, after all referenced tables and
-- functions exist. Statement guards make CASCADE unable to bypass custody.
CREATE TRIGGER workflow_plan_v2_selection_horizon_update
BEFORE UPDATE ON workflow_plan_v2_work_selection_replay_horizons
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_work_selection_horizon();

CREATE TRIGGER workflow_plan_v2_selection_horizon_delete
BEFORE DELETE ON workflow_plan_v2_work_selection_replay_horizons
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_selection_horizon_truncate
BEFORE TRUNCATE ON workflow_plan_v2_work_selection_replay_horizons
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_activation_selection_validate
BEFORE INSERT OR UPDATE ON workflow_plan_v2_activation_work_selections
FOR EACH ROW
EXECUTE FUNCTION automata_validate_activation_work_selection_transition();

CREATE TRIGGER workflow_plan_v2_materialization_selection_validate
BEFORE INSERT OR UPDATE ON workflow_plan_v2_materialization_work_selections
FOR EACH ROW
EXECUTE FUNCTION automata_validate_materialization_work_selection_transition();

CREATE TRIGGER workflow_plan_v2_activation_selection_delete
BEFORE DELETE ON workflow_plan_v2_activation_work_selections
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_activation_selection_receipt_delete();

CREATE TRIGGER workflow_plan_v2_materialization_selection_delete
BEFORE DELETE ON workflow_plan_v2_materialization_work_selections
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_materialization_selection_receipt_delete();

CREATE TRIGGER workflow_plan_v2_activation_selection_truncate
BEFORE TRUNCATE ON workflow_plan_v2_activation_work_selections
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_materialization_selection_truncate
BEFORE TRUNCATE ON workflow_plan_v2_materialization_work_selections
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_activation_selection_finalize
AFTER INSERT OR UPDATE ON workflow_plan_v2_activation_work_selections
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_final_activation_work_selection();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_materialization_selection_finalize
AFTER INSERT OR UPDATE ON workflow_plan_v2_materialization_work_selections
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_final_materialization_work_selection();

CREATE TRIGGER workflow_plan_v2_activation_quarantine_validate
BEFORE INSERT ON workflow_plan_v2_activation_work_quarantines
FOR EACH ROW
EXECUTE FUNCTION automata_validate_activation_real_claim_quarantine();

CREATE TRIGGER workflow_plan_v2_materialization_quarantine_validate
BEFORE INSERT ON workflow_plan_v2_materialization_work_quarantines
FOR EACH ROW
EXECUTE FUNCTION automata_validate_materialization_real_claim_quarantine();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_activation_quarantine_selection_closure
AFTER INSERT ON workflow_plan_v2_activation_work_quarantines
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_final_activation_work_quarantine();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_materialization_quarantine_selection_closure
AFTER INSERT ON workflow_plan_v2_materialization_work_quarantines
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_final_materialization_work_quarantine();

CREATE TRIGGER workflow_plan_v2_activation_quarantine_immutable
BEFORE UPDATE OR DELETE ON workflow_plan_v2_activation_work_quarantines
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_materialization_quarantine_immutable
BEFORE UPDATE OR DELETE ON workflow_plan_v2_materialization_work_quarantines
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_activation_quarantine_truncate
BEFORE TRUNCATE ON workflow_plan_v2_activation_work_quarantines
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_materialization_quarantine_truncate
BEFORE TRUNCATE ON workflow_plan_v2_materialization_work_quarantines
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_preparation_claim_lineage
AFTER INSERT OR UPDATE ON workflow_plan_v2_activation_preparation_claims
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_preparation_claim_lineage();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_activation_claim_lineage
AFTER UPDATE ON workflow_plan_v2_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_activation_claim_lineage();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_materialization_claim_lineage
AFTER INSERT OR UPDATE ON workflow_plan_v2_materialization_claims
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_materialization_claim_lineage();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_preparation_claim_closure
AFTER INSERT OR UPDATE ON workflow_plan_v2_activation_preparation_claims
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_preparation_binding_state_closure();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_preparation_binding_closure
AFTER INSERT ON workflow_plan_v2_activation_preparations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_preparation_binding_state_closure();

CREATE TRIGGER workflow_plan_v2_concrete_jobs_01_live_authority
BEFORE INSERT ON workflow_plan_v2_concrete_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_require_live_concrete_job_authority();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_materialization_claim_closure
AFTER INSERT OR UPDATE ON workflow_plan_v2_materialization_claims
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_materialization_state_closure();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_concrete_job_closure
AFTER INSERT ON workflow_plan_v2_concrete_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_materialization_state_closure();

CREATE TRIGGER workflow_plan_v2_preparation_claims_truncate
BEFORE TRUNCATE ON workflow_plan_v2_activation_preparation_claims
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_preparations_truncate
BEFORE TRUNCATE ON workflow_plan_v2_activation_preparations
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_preparation_prerequisites_truncate
BEFORE TRUNCATE ON workflow_plan_v2_activation_preparation_prerequisites
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_preparation_outputs_truncate
BEFORE TRUNCATE ON workflow_plan_v2_activation_preparation_outputs
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_work_evidence_mutation();
