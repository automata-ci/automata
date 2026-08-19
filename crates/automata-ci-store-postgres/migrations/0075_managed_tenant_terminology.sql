-- The externally managed isolation boundary is a Core tenant. Rename the
-- provisional workspace vocabulary without rewriting frozen migration history.

ALTER TABLE workspace_provisioning_operations
    RENAME TO tenant_provisioning_operations;
ALTER TABLE tenant_provisioning_operations
    RENAME COLUMN workspace_id TO tenant_id;
ALTER TABLE tenant_provisioning_operations
    RENAME COLUMN workspace_display_name TO tenant_display_name;

ALTER TABLE workspace_management_bindings
    RENAME TO tenant_management_bindings;
ALTER TABLE tenant_management_bindings
    RENAME COLUMN workspace_id TO tenant_id;

ALTER TABLE workspace_entitlement_operations
    RENAME TO tenant_entitlement_operations;
ALTER TABLE tenant_entitlement_operations
    RENAME COLUMN workspace_id TO tenant_id;

ALTER TABLE workspace_execution_entitlements
    RENAME TO tenant_execution_entitlements;
ALTER TABLE tenant_execution_entitlements
    RENAME COLUMN workspace_id TO tenant_id;

ALTER TABLE workspace_usage_events
    RENAME TO tenant_usage_events;
ALTER TABLE tenant_usage_events
    RENAME COLUMN workspace_id TO tenant_id;
ALTER SEQUENCE workspace_usage_events_sequence_seq
    RENAME TO tenant_usage_events_sequence_seq;

ALTER TABLE workspace_github_repository_operations
    RENAME TO tenant_github_repository_operations;
ALTER TABLE tenant_github_repository_operations
    RENAME COLUMN workspace_id TO tenant_id;

ALTER TABLE workspace_github_repository_current
    RENAME TO tenant_github_repository_current;
ALTER TABLE tenant_github_repository_current
    RENAME COLUMN workspace_id TO tenant_id;

ALTER TABLE workspace_github_repository_selections
    RENAME TO tenant_github_repository_selections;
ALTER TABLE tenant_github_repository_selections
    RENAME COLUMN workspace_id TO tenant_id;

ALTER TABLE workspace_github_repository_installation_bindings
    RENAME TO tenant_github_repository_installation_bindings;
ALTER TABLE tenant_github_repository_installation_bindings
    RENAME COLUMN workspace_id TO tenant_id;

ALTER TABLE provider_connection_revisions
    RENAME COLUMN workspace_id TO tenant_id;

-- PostgreSQL preserves constraint and index identifiers when their owning
-- relation or column is renamed. Rename those catalog objects as well so new
-- diagnostics and schema inspection contain only the accepted tenant term.
DO $$
DECLARE
    relation_name TEXT;
    constraint_row RECORD;
    index_row RECORD;
    replacement_name TEXT;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'tenant_provisioning_operations',
        'tenant_management_bindings',
        'tenant_entitlement_operations',
        'tenant_execution_entitlements',
        'tenant_usage_events',
        'tenant_github_repository_operations',
        'tenant_github_repository_current',
        'tenant_github_repository_selections',
        'tenant_github_repository_installation_bindings',
        'provider_connection_revisions'
    ]
    LOOP
        FOR constraint_row IN
            SELECT constraint_catalog.oid, constraint_catalog.conname
            FROM pg_catalog.pg_constraint AS constraint_catalog
            WHERE constraint_catalog.conrelid = relation_name::REGCLASS
              AND constraint_catalog.conname LIKE '%workspace%'
            ORDER BY constraint_catalog.conname
        LOOP
            replacement_name := pg_catalog.replace(
                constraint_row.conname,
                'workspace',
                'tenant'
            );
            EXECUTE pg_catalog.format(
                'ALTER TABLE %I RENAME CONSTRAINT %I TO %I',
                relation_name,
                constraint_row.conname,
                replacement_name
            );
        END LOOP;

        FOR index_row IN
            SELECT index_relation.relname
            FROM pg_catalog.pg_index AS index_catalog
            JOIN pg_catalog.pg_class AS index_relation
              ON index_relation.oid = index_catalog.indexrelid
            WHERE index_catalog.indrelid = relation_name::REGCLASS
              AND index_relation.relname LIKE '%workspace%'
            ORDER BY index_relation.relname
        LOOP
            replacement_name := pg_catalog.replace(
                index_row.relname,
                'workspace',
                'tenant'
            );
            EXECUTE pg_catalog.format(
                'ALTER INDEX %I RENAME TO %I',
                index_row.relname,
                replacement_name
            );
        END LOOP;
    END LOOP;
END;
$$;

LOCK TABLE rbac_roles IN SHARE MODE;

UPDATE rbac_roles
SET name = 'tenant-owner',
    display_name = 'Tenant owner',
    revision = revision + 1,
    updated_at_ms = GREATEST(
        updated_at_ms,
        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
    )
WHERE name = 'workspace-owner'
  AND role_kind = 'built_in'
  AND immutable;

UPDATE rbac_permissions
SET description = CASE name
    WHEN 'billing:read'
        THEN 'Read tenant billing, usage, invoice, and payment status.'
    WHEN 'billing:manage'
        THEN 'Manage tenant payment methods and subscription lifecycle.'
    ELSE description
END
WHERE name IN ('billing:read', 'billing:manage');

-- This trigger function was created before provider connections adopted the
-- common tenant column. Replace the exact current body after the column rename.
CREATE OR REPLACE FUNCTION automata_require_current_manifest_runtime_policy_pair()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    pair_exists BOOLEAN;
BEGIN
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
        WHERE current_policy.tenant_id = NEW.tenant_id
          AND current_policy.repository_id = NEW.repository_id
          AND manifest.runtime_policy_revision = current_policy.policy_revision
          AND manifest.runtime_policy_digest = current_policy.policy_digest
    ) OR EXISTS (
        SELECT 1
        FROM workflow_runtime_policy_current AS current_policy
        JOIN workflow_runtime_policy_revisions AS policy
          ON policy.tenant_id = current_policy.tenant_id
         AND policy.repository_id = current_policy.repository_id
         AND policy.policy_revision = current_policy.policy_revision
         AND policy.policy_digest = current_policy.policy_digest
         AND policy.state = 'sealed'
        JOIN repositories AS repository
          ON repository.tenant_id = current_policy.tenant_id
         AND repository.id = current_policy.repository_id
        JOIN provider_connection_revisions AS connection
          ON connection.tenant_id = repository.tenant_id
         AND connection.external_repository_id = repository.provider_repository_id
         AND connection.lifecycle_state = 'active'
         AND connection.runner_policy_schema = policy.policy_schema
         AND connection.runner_policy_digest = pg_catalog.sha256(policy.canonical_policy)
        JOIN provider_instance_revisions AS provider
          ON provider.instance_id = connection.provider_instance_id
         AND provider.revision = connection.provider_revision
         AND provider.provider_type = repository.scm_provider
         AND provider.configuration_digest = connection.provider_configuration_digest
         AND provider.capability_digest = connection.capability_digest
         AND provider.lifecycle_state = 'active'
        WHERE current_policy.tenant_id = NEW.tenant_id
          AND current_policy.repository_id = NEW.repository_id
    ) INTO pair_exists;
    IF pair_exists IS NOT TRUE THEN
        RAISE EXCEPTION 'current provider manifest and runtime policy are not an exact pair'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_current_runtime_policy_pair';
    END IF;
    RETURN NULL;
END;
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND (
              relation.relname LIKE 'workspace\_provisioning%' ESCAPE '\'
              OR relation.relname LIKE 'workspace\_management%' ESCAPE '\'
              OR relation.relname LIKE 'workspace\_entitlement%' ESCAPE '\'
              OR relation.relname LIKE 'workspace\_execution%' ESCAPE '\'
              OR relation.relname LIKE 'workspace\_usage%' ESCAPE '\'
              OR relation.relname LIKE 'workspace\_github%' ESCAPE '\'
              OR relation.relname = 'provider_connections_by_workspace'
          )
    ) THEN
        RAISE EXCEPTION 'managed workspace relation survived tenant terminology migration';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns AS column_catalog
        WHERE column_catalog.table_schema = 'public'
          AND column_catalog.column_name IN ('workspace_id', 'workspace_display_name')
    ) THEN
        RAISE EXCEPTION 'managed workspace column survived tenant terminology migration';
    END IF;
END;
$$;
