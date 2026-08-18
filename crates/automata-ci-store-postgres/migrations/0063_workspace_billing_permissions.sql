INSERT INTO rbac_permissions (
    name, description, critical, created_at_ms
) VALUES
    (
        'billing:read',
        'Read workspace billing, usage, invoice, and payment status.',
        TRUE,
        0
    ),
    (
        'billing:manage',
        'Manage workspace payment methods and subscription lifecycle.',
        TRUE,
        0
    );

WITH database_clock AS (
    SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
), owner_roles AS (
    SELECT tenant_id, id, created_by_principal_id
    FROM rbac_roles
    WHERE name = 'workspace-owner'
      AND role_kind = 'built_in'
      AND immutable
), billing_permissions(name) AS (
    VALUES ('billing:read'::TEXT), ('billing:manage'::TEXT)
)
INSERT INTO rbac_role_permissions (
    tenant_id, role_id, permission_name,
    granted_by_principal_id, granted_at_ms
)
SELECT
    role.tenant_id,
    role.id,
    permission.name,
    role.created_by_principal_id,
    clock.now_ms
FROM owner_roles AS role
CROSS JOIN billing_permissions AS permission
CROSS JOIN database_clock AS clock;
