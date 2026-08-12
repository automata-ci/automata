-- Conformance exports expose privileged target-native execution evidence and
-- are never authorized by repository publication policy. Existing immutable
-- installation-owner roles receive the new catalog permission so upgrades
-- preserve the authority originally granted to the bootstrap owner.

INSERT INTO rbac_permissions (name, description, critical, created_at_ms)
VALUES (
    'conformance:read',
    'Export private workflow execution evidence for conformance testing.',
    TRUE,
    0
);

INSERT INTO rbac_role_permissions (
    tenant_id,
    role_id,
    permission_name,
    granted_by_principal_id,
    granted_at_ms
)
SELECT role.tenant_id,
       role.id,
       'conformance:read',
       role.created_by_principal_id,
       role.updated_at_ms
FROM rbac_roles AS role
WHERE role.role_kind = 'built_in'
  AND role.immutable
  AND role.name = 'installation-owner';
