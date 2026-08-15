-- Canonical catalog rows.
INSERT INTO automata_cluster_compatibility (
    singleton, minimum_admission_epoch, job_ir_schema, runner_requirements_schema
) VALUES (TRUE, 1, 1, 1);

WITH database_clock AS (
    SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
)
INSERT INTO logical_workflow_result_selection_replay_horizons (
    queue_name, replay_floor_ms, updated_at_ms
)
SELECT queue_name, now_ms, now_ms
FROM database_clock
CROSS JOIN (VALUES ('instance'), ('job')) AS queue(queue_name);

WITH database_clock AS (
    SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
)
INSERT INTO logical_workflow_work_selection_replay_horizons (
    queue_name, replay_floor_ms, updated_at_ms
)
SELECT queue_name, greatest(0, now_ms - 60000), now_ms
FROM database_clock
CROSS JOIN (VALUES ('activation'), ('materialization')) AS queue(queue_name);

INSERT INTO human_auth_installation_state (singleton, state, bootstrap_token_hash, bootstrap_hash_key_id, expected_provider_id, expected_provider_subject, challenge_expires_at_ms, configured_tenant_id, configured_principal_id, configured_at_ms, revision, created_at_ms, updated_at_ms, target_tenant_id, target_tenant_display_name, setup_transaction_id) VALUES (true, 'unconfigured', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, 0, 0, NULL, NULL, NULL);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('tenant:read', 'Read tenant configuration.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('tenant:settings:update', 'Update tenant configuration.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('tenant:delete', 'Delete a tenant and its retained resources.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('tenant:ownership:transfer', 'Transfer tenant ownership authority.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('members:read', 'Read tenant members.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('members:manage', 'Invite, suspend, and restore tenant members.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('roles:read', 'Read roles and permission grants.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('roles:manage', 'Create roles and change their permission grants.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('role-bindings:manage', 'Grant and revoke scoped roles.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('auth-mappings:read', 'Read external membership role mappings.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('auth-mappings:manage', 'Change external membership role mappings.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('sessions:read:self', 'Read the caller own sessions.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('sessions:revoke:self', 'Revoke the caller own sessions.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('sessions:read:any', 'Read sessions belonging to other members.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('sessions:revoke:any', 'Revoke sessions belonging to other members.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('audit:read', 'Read immutable security audit events.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('repositories:read', 'Read private repositories.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('repositories:create', 'Create repositories.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('repositories:settings:update', 'Update repository settings.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('repositories:visibility:update', 'Change repository publication audiences.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('repositories:access:manage', 'Manage repository-scoped access.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('repositories:delete', 'Delete repositories.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('workflows:read', 'Read workflow definitions.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('workflows:manage', 'Create and change workflow definitions.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('runs:read', 'Read workflow runs.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('runs:dispatch', 'Dispatch workflow runs.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('runs:cancel', 'Cancel workflow runs.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('runs:rerun', 'Rerun workflow runs.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('jobs:read', 'Read jobs and attempts.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('logs:read', 'Read private job logs.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('artifacts:read', 'Read private artifact metadata.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('artifacts:download', 'Download private artifacts.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('artifacts:delete', 'Delete artifacts.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('caches:read', 'Read cache metadata.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('caches:delete', 'Delete caches.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('secrets:metadata:read', 'Read secret metadata without values.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('secrets:create', 'Create secret values without readback.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('secrets:update', 'Replace secret values without readback.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('secrets:delete', 'Delete secrets.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('secrets:policy:manage', 'Manage secret access policy.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('secret-providers:read', 'Read redacted secret-provider configuration.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('secret-providers:manage', 'Manage secret providers.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('secret-keys:rotate', 'Rotate secret encryption keys.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('environments:read', 'Read environment configuration.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('environments:manage', 'Manage environments and protection rules.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('environments:approve', 'Approve protected environment use.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('runners:read', 'Read runners and runner groups.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('runners:manage', 'Change runner lifecycle state.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('runners:enroll', 'Enroll new runners.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('runner-groups:read', 'Read runner groups and routing policy.', false, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('runner-groups:manage', 'Manage runner groups and routing policy.', true, 0);
INSERT INTO rbac_permissions (name, description, critical, created_at_ms) VALUES ('conformance:read', 'Export private workflow execution evidence for conformance testing.', true, 0);
