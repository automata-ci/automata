-- Human authentication, tenant-scoped RBAC, immutable security auditing, and
-- repository publication policy. Existing and future repositories are private
-- unless an authorized writer explicitly broadens one audience.

ALTER TABLE tenants
    ADD COLUMN login_admission_mode TEXT NOT NULL DEFAULT 'restricted',
    ADD COLUMN authorization_revision BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT tenants_login_admission_mode CHECK (
        login_admission_mode IN ('restricted', 'open_sign_in')
    ),
    ADD CONSTRAINT tenants_authorization_revision_positive CHECK (
        authorization_revision > 0
    );

CREATE TABLE human_principals (
    id UUID PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'active',
    display_name TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    disabled_at_ms BIGINT,
    disabled_reason TEXT,
    CONSTRAINT human_principals_status CHECK (status IN ('active', 'disabled')),
    CONSTRAINT human_principals_display_name_shape CHECK (
        display_name IS NULL OR (
            octet_length(display_name) <= 1024
            AND display_name !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT human_principals_revision_positive CHECK (revision > 0),
    CONSTRAINT human_principals_time_monotonic CHECK (updated_at_ms >= created_at_ms),
    CONSTRAINT human_principals_disabled_shape CHECK ((
        (
            status = 'active'
            AND disabled_at_ms IS NULL
            AND disabled_reason IS NULL
        ) OR (
            status = 'disabled'
            AND disabled_at_ms >= created_at_ms
            AND octet_length(disabled_reason) BETWEEN 1 AND 1024
            AND disabled_reason !~ '[[:cntrl:]]'
        )
    ) IS TRUE)
);

CREATE TABLE human_provider_identities (
    principal_id UUID NOT NULL REFERENCES human_principals(id) ON DELETE RESTRICT,
    provider_id TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    provider_login TEXT NOT NULL,
    normalized_login TEXT NOT NULL,
    display_name TEXT,
    first_authenticated_at_ms BIGINT NOT NULL,
    last_authenticated_at_ms BIGINT NOT NULL,
    last_observed_at_ms BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT human_provider_identities_primary_key PRIMARY KEY (
        provider_id, provider_subject
    ),
    CONSTRAINT human_provider_identities_principal_provider_unique UNIQUE (
        principal_id, provider_id
    ),
    CONSTRAINT human_provider_identities_principal_identity_unique UNIQUE (
        principal_id, provider_id, provider_subject
    ),
    CONSTRAINT human_provider_identities_provider_shape CHECK (
        octet_length(provider_id) BETWEEN 1 AND 128
        AND provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT human_provider_identities_subject_shape CHECK (
        octet_length(provider_subject) BETWEEN 1 AND 255
        AND provider_subject !~ '[[:cntrl:]]'
    ),
    CONSTRAINT human_provider_identities_login_shape CHECK (
        octet_length(provider_login) BETWEEN 1 AND 255
        AND provider_login !~ '[[:cntrl:]]'
        AND octet_length(normalized_login) BETWEEN 1 AND 255
        AND normalized_login !~ '[[:cntrl:]]'
    ),
    CONSTRAINT human_provider_identities_display_name_shape CHECK (
        display_name IS NULL OR (
            octet_length(display_name) <= 1024
            AND display_name !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT human_provider_identities_revision_positive CHECK (revision > 0),
    CONSTRAINT human_provider_identities_time_monotonic CHECK (
        updated_at_ms >= created_at_ms
        AND last_authenticated_at_ms >= first_authenticated_at_ms
        AND last_observed_at_ms >= first_authenticated_at_ms
    )
);

CREATE INDEX human_provider_identities_login_lookup
    ON human_provider_identities (provider_id, normalized_login);

CREATE TABLE tenant_human_memberships (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    principal_id UUID NOT NULL REFERENCES human_principals(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'active',
    authorization_revision BIGINT NOT NULL DEFAULT 1,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    suspended_at_ms BIGINT,
    suspended_reason TEXT,
    CONSTRAINT tenant_human_memberships_primary_key PRIMARY KEY (
        tenant_id, principal_id
    ),
    CONSTRAINT tenant_human_memberships_status CHECK (
        status IN ('active', 'suspended')
    ),
    CONSTRAINT tenant_human_memberships_revision_positive CHECK (revision > 0),
    CONSTRAINT tenant_human_memberships_authorization_revision_positive CHECK (
        authorization_revision > 0
    ),
    CONSTRAINT tenant_human_memberships_time_monotonic CHECK (
        updated_at_ms >= created_at_ms
    ),
    CONSTRAINT tenant_human_memberships_suspension_shape CHECK ((
        (
            status = 'active'
            AND suspended_at_ms IS NULL
            AND suspended_reason IS NULL
        ) OR (
            status = 'suspended'
            AND suspended_at_ms >= created_at_ms
            AND octet_length(suspended_reason) BETWEEN 1 AND 1024
            AND suspended_reason !~ '[[:cntrl:]]'
        )
    ) IS TRUE)
);

CREATE INDEX tenant_human_memberships_principal
    ON tenant_human_memberships (principal_id, tenant_id);

-- This singleton is intentionally not a "first user wins" switch. A pending
-- setup binds a keyed bootstrap-token digest and an exact provider subject.
CREATE TABLE human_auth_installation_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    state TEXT NOT NULL,
    bootstrap_token_hash BYTEA,
    bootstrap_hash_key_id TEXT,
    expected_provider_id TEXT,
    expected_provider_subject TEXT,
    challenge_expires_at_ms BIGINT,
    configured_tenant_id TEXT,
    configured_principal_id UUID,
    configured_at_ms BIGINT,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT human_auth_installation_state_singleton CHECK (singleton),
    CONSTRAINT human_auth_installation_state_state CHECK (
        state IN ('unconfigured', 'pending', 'configured')
    ),
    CONSTRAINT human_auth_installation_state_revision_positive CHECK (revision > 0),
    CONSTRAINT human_auth_installation_state_time_monotonic CHECK (
        updated_at_ms >= created_at_ms
    ),
    CONSTRAINT human_auth_installation_state_shape CHECK ((
        (
            state = 'unconfigured'
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND expected_provider_id IS NULL
            AND expected_provider_subject IS NULL
            AND challenge_expires_at_ms IS NULL
            AND configured_tenant_id IS NULL
            AND configured_principal_id IS NULL
            AND configured_at_ms IS NULL
        ) OR (
            state = 'pending'
            AND octet_length(bootstrap_token_hash) = 32
            AND octet_length(bootstrap_hash_key_id) BETWEEN 1 AND 128
            AND bootstrap_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_id) BETWEEN 1 AND 128
            AND expected_provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_subject) BETWEEN 1 AND 255
            AND expected_provider_subject !~ '[[:cntrl:]]'
            AND challenge_expires_at_ms > updated_at_ms
            AND configured_tenant_id IS NULL
            AND configured_principal_id IS NULL
            AND configured_at_ms IS NULL
        ) OR (
            state = 'configured'
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND octet_length(expected_provider_id) BETWEEN 1 AND 128
            AND octet_length(expected_provider_subject) BETWEEN 1 AND 255
            AND challenge_expires_at_ms IS NULL
            AND configured_tenant_id IS NOT NULL
            AND configured_principal_id IS NOT NULL
            AND configured_at_ms >= created_at_ms
        )
    ) IS TRUE),
    CONSTRAINT human_auth_installation_state_membership
        FOREIGN KEY (configured_tenant_id, configured_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT human_auth_installation_state_identity
        FOREIGN KEY (
            configured_principal_id, expected_provider_id, expected_provider_subject
        ) REFERENCES human_provider_identities(
            principal_id, provider_id, provider_subject
        ) ON DELETE RESTRICT
);

INSERT INTO human_auth_installation_state (
    singleton, state, revision, created_at_ms, updated_at_ms
) VALUES (TRUE, 'unconfigured', 1, 0, 0);

-- Both browser PKCE verifiers and provider device codes are held only inside
-- the authenticated encrypted payload. Browser state, browser binding, and CLI
-- poll proofs are persisted as fixed-length keyed hashes.
CREATE TABLE human_login_transactions (
    id UUID PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id) ON DELETE RESTRICT,
    purpose TEXT NOT NULL,
    flow_kind TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    return_path TEXT,
    state_hash BYTEA,
    state_hash_key_id TEXT,
    browser_binding_hash BYTEA,
    browser_binding_hash_key_id TEXT,
    poll_proof_hash BYTEA,
    poll_proof_hash_key_id TEXT,
    encrypted_payload BYTEA NOT NULL,
    payload_nonce BYTEA NOT NULL,
    wrapped_data_key BYTEA NOT NULL,
    encryption_key_id TEXT NOT NULL,
    encryption_schema INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    completed_principal_id UUID,
    poll_interval_ms BIGINT,
    next_poll_at_ms BIGINT,
    poll_attempts INTEGER NOT NULL DEFAULT 0,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    consumed_at_ms BIGINT,
    revision BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT human_login_transactions_purpose CHECK (
        purpose IN ('sign_in', 'installation_setup')
    ),
    CONSTRAINT human_login_transactions_flow_kind CHECK (
        flow_kind IN ('browser', 'device')
    ),
    CONSTRAINT human_login_transactions_provider_shape CHECK (
        octet_length(provider_id) BETWEEN 1 AND 128
        AND provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT human_login_transactions_purpose_tenant CHECK ((
        (purpose = 'sign_in' AND tenant_id IS NOT NULL)
        OR (purpose = 'installation_setup' AND tenant_id IS NULL)
    ) IS TRUE),
    CONSTRAINT human_login_transactions_return_path_shape CHECK (
        return_path IS NULL OR (
            octet_length(return_path) BETWEEN 1 AND 2048
            AND left(return_path, 1) = '/'
            AND left(return_path, 2) <> '//'
            AND return_path !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT human_login_transactions_envelope_shape CHECK (
        octet_length(encrypted_payload) BETWEEN 17 AND 67681
        AND octet_length(payload_nonce) = 12
        AND octet_length(wrapped_data_key) BETWEEN 1 AND 65536
        AND octet_length(encryption_key_id) BETWEEN 1 AND 128
        AND encryption_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        AND encryption_schema = 1
    ),
    CONSTRAINT human_login_transactions_hash_key_shape CHECK (
        (state_hash_key_id IS NULL OR (
            octet_length(state_hash_key_id) BETWEEN 1 AND 128
            AND state_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        ))
        AND (browser_binding_hash_key_id IS NULL OR (
            octet_length(browser_binding_hash_key_id) BETWEEN 1 AND 128
            AND browser_binding_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        ))
        AND (poll_proof_hash_key_id IS NULL OR (
            octet_length(poll_proof_hash_key_id) BETWEEN 1 AND 128
            AND poll_proof_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        ))
    ),
    CONSTRAINT human_login_transactions_flow_shape CHECK ((
        (
            flow_kind = 'browser'
            AND octet_length(state_hash) = 32
            AND state_hash_key_id IS NOT NULL
            AND octet_length(browser_binding_hash) = 32
            AND browser_binding_hash_key_id IS NOT NULL
            AND poll_proof_hash IS NULL
            AND poll_proof_hash_key_id IS NULL
            AND poll_interval_ms IS NULL
            AND next_poll_at_ms IS NULL
        ) OR (
            flow_kind = 'device'
            AND state_hash IS NULL
            AND state_hash_key_id IS NULL
            AND browser_binding_hash IS NULL
            AND browser_binding_hash_key_id IS NULL
            AND octet_length(poll_proof_hash) = 32
            AND poll_proof_hash_key_id IS NOT NULL
            AND poll_interval_ms BETWEEN 1000 AND 300000
            AND next_poll_at_ms > created_at_ms
        )
    ) IS TRUE),
    CONSTRAINT human_login_transactions_status CHECK (
        status IN ('pending', 'consumed', 'succeeded', 'denied', 'expired')
    ),
    CONSTRAINT human_login_transactions_status_shape CHECK ((
        (
            status = 'pending'
            AND completed_principal_id IS NULL
            AND consumed_at_ms IS NULL
        ) OR (
            status = 'succeeded'
            AND completed_principal_id IS NOT NULL
            AND consumed_at_ms >= created_at_ms
        ) OR (
            status IN ('consumed', 'denied', 'expired')
            AND completed_principal_id IS NULL
            AND consumed_at_ms >= created_at_ms
        )
    ) IS TRUE),
    CONSTRAINT human_login_transactions_poll_attempts_nonnegative CHECK (
        poll_attempts >= 0
    ),
    CONSTRAINT human_login_transactions_revision_positive CHECK (revision > 0),
    CONSTRAINT human_login_transactions_lifetime CHECK (
        updated_at_ms >= created_at_ms
        AND expires_at_ms > created_at_ms
        AND (consumed_at_ms IS NULL OR consumed_at_ms <= updated_at_ms)
    ),
    CONSTRAINT human_login_transactions_completed_principal
        FOREIGN KEY (completed_principal_id)
        REFERENCES human_principals(id) ON DELETE RESTRICT,
    CONSTRAINT human_login_transactions_completed_membership
        FOREIGN KEY (tenant_id, completed_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX human_login_transactions_live_browser_state
    ON human_login_transactions (provider_id, state_hash_key_id, state_hash)
    WHERE flow_kind = 'browser' AND status = 'pending';

CREATE UNIQUE INDEX human_login_transactions_live_poll_proof
    ON human_login_transactions (poll_proof_hash_key_id, poll_proof_hash)
    WHERE flow_kind = 'device' AND status = 'pending';

CREATE INDEX human_login_transactions_expiry
    ON human_login_transactions (expires_at_ms, id)
    WHERE status = 'pending';

CREATE INDEX human_login_transactions_device_poll
    ON human_login_transactions (next_poll_at_ms, id)
    WHERE flow_kind = 'device' AND status = 'pending';

-- Provider access and refresh tokens share one authenticated envelope. Revoking
-- a record destroys all encrypted key material instead of retaining stale
-- credentials. Version is the compare-and-swap rotation fence.
CREATE TABLE human_provider_tokens (
    tenant_id TEXT NOT NULL,
    principal_id UUID NOT NULL,
    provider_id TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    version BIGINT NOT NULL,
    grant_kind TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    encrypted_payload BYTEA,
    payload_nonce BYTEA,
    wrapped_data_key BYTEA,
    encryption_key_id TEXT,
    encryption_schema INTEGER,
    issued_at_ms BIGINT NOT NULL,
    access_expires_at_ms BIGINT NOT NULL,
    refresh_expires_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT,
    revocation_reason TEXT,
    CONSTRAINT human_provider_tokens_primary_key PRIMARY KEY (
        tenant_id, provider_id, provider_subject
    ),
    CONSTRAINT human_provider_tokens_membership
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT human_provider_tokens_identity
        FOREIGN KEY (principal_id, provider_id, provider_subject)
        REFERENCES human_provider_identities(principal_id, provider_id, provider_subject)
        ON DELETE RESTRICT,
    CONSTRAINT human_provider_tokens_version_positive CHECK (version > 0),
    CONSTRAINT human_provider_tokens_grant_kind CHECK (
        grant_kind IN ('browser_authorization_code', 'device_authorization', 'refresh')
    ),
    CONSTRAINT human_provider_tokens_scopes_bounded CHECK (
        cardinality(scopes) <= 256
        AND array_position(scopes, NULL) IS NULL
    ),
    CONSTRAINT human_provider_tokens_envelope_shape CHECK ((
        (
            revoked_at_ms IS NULL
            AND revocation_reason IS NULL
            AND octet_length(encrypted_payload) BETWEEN 17 AND 1048592
            AND octet_length(payload_nonce) = 12
            AND octet_length(wrapped_data_key) BETWEEN 1 AND 65536
            AND octet_length(encryption_key_id) BETWEEN 1 AND 128
            AND encryption_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
            AND encryption_schema = 1
        ) OR (
            revoked_at_ms >= issued_at_ms
            AND octet_length(revocation_reason) BETWEEN 1 AND 1024
            AND revocation_reason !~ '[[:cntrl:]]'
            AND encrypted_payload IS NULL
            AND payload_nonce IS NULL
            AND wrapped_data_key IS NULL
            AND encryption_key_id IS NULL
            AND encryption_schema IS NULL
        )
    ) IS TRUE),
    CONSTRAINT human_provider_tokens_lifetime CHECK (
        access_expires_at_ms > issued_at_ms
        AND (
            refresh_expires_at_ms IS NULL
            OR refresh_expires_at_ms > access_expires_at_ms
        )
        AND updated_at_ms >= created_at_ms
    )
);

CREATE INDEX human_provider_tokens_refresh_due
    ON human_provider_tokens (access_expires_at_ms, tenant_id, provider_id, provider_subject)
    WHERE revoked_at_ms IS NULL;

-- Automata bearer material is never stored: only a keyed fixed-length digest.
-- Browser and CLI audiences are distinct and cannot be replayed across surfaces.
CREATE TABLE human_sessions (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    principal_id UUID NOT NULL,
    provider_id TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    session_kind TEXT NOT NULL,
    audience TEXT NOT NULL,
    token_hash BYTEA NOT NULL,
    token_hash_key_id TEXT NOT NULL,
    authorization_revision BIGINT NOT NULL,
    predecessor_session_id UUID,
    issued_at_ms BIGINT NOT NULL,
    last_seen_at_ms BIGINT NOT NULL,
    idle_expires_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT,
    revocation_reason TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT human_sessions_tenant_id_unique UNIQUE (tenant_id, id),
    CONSTRAINT human_sessions_actor_unique UNIQUE (tenant_id, principal_id, id),
    CONSTRAINT human_sessions_membership
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT human_sessions_identity
        FOREIGN KEY (principal_id, provider_id, provider_subject)
        REFERENCES human_provider_identities(principal_id, provider_id, provider_subject)
        ON DELETE RESTRICT,
    CONSTRAINT human_sessions_kind_audience CHECK (
        (session_kind = 'browser' AND audience = 'automata.web')
        OR (session_kind = 'cli' AND audience = 'automata.cli')
    ),
    CONSTRAINT human_sessions_token_hash CHECK (octet_length(token_hash) = 32),
    CONSTRAINT human_sessions_token_hash_key_shape CHECK (
        octet_length(token_hash_key_id) BETWEEN 1 AND 128
        AND token_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT human_sessions_token_hash_unique UNIQUE (token_hash_key_id, token_hash),
    CONSTRAINT human_sessions_authorization_revision_positive CHECK (
        authorization_revision > 0
    ),
    CONSTRAINT human_sessions_predecessor
        FOREIGN KEY (tenant_id, predecessor_session_id)
        REFERENCES human_sessions(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT human_sessions_lifetime CHECK (
        last_seen_at_ms >= issued_at_ms
        AND idle_expires_at_ms > last_seen_at_ms
        AND idle_expires_at_ms <= expires_at_ms
        AND expires_at_ms > issued_at_ms
    ),
    CONSTRAINT human_sessions_revocation_shape CHECK ((
        (
            revoked_at_ms IS NULL
            AND revocation_reason IS NULL
        ) OR (
            revoked_at_ms >= issued_at_ms
            AND octet_length(revocation_reason) BETWEEN 1 AND 1024
            AND revocation_reason !~ '[[:cntrl:]]'
        )
    ) IS TRUE),
    CONSTRAINT human_sessions_revision_positive CHECK (revision > 0)
);

CREATE INDEX human_sessions_active_token_lookup
    ON human_sessions (token_hash_key_id, token_hash, expires_at_ms)
    WHERE revoked_at_ms IS NULL;

CREATE INDEX human_sessions_principal_activity
    ON human_sessions (tenant_id, principal_id, issued_at_ms DESC, id)
    WHERE revoked_at_ms IS NULL;

CREATE INDEX human_sessions_expiry
    ON human_sessions (expires_at_ms, id)
    WHERE revoked_at_ms IS NULL;

CREATE TABLE rbac_permissions (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    critical BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_ms BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT rbac_permissions_name_shape CHECK (
        octet_length(name) BETWEEN 1 AND 128
        AND name ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT rbac_permissions_description_shape CHECK (
        octet_length(description) BETWEEN 1 AND 1024
        AND description !~ '[[:cntrl:]]'
    ),
    CONSTRAINT rbac_permissions_created_nonnegative CHECK (created_at_ms >= 0)
);

INSERT INTO rbac_permissions (name, description, critical) VALUES
    ('tenant:read', 'Read tenant configuration.', FALSE),
    ('tenant:settings:update', 'Update tenant configuration.', TRUE),
    ('tenant:delete', 'Delete a tenant and its retained resources.', TRUE),
    ('tenant:ownership:transfer', 'Transfer tenant ownership authority.', TRUE),
    ('members:read', 'Read tenant members.', FALSE),
    ('members:manage', 'Invite, suspend, and restore tenant members.', TRUE),
    ('roles:read', 'Read roles and permission grants.', FALSE),
    ('roles:manage', 'Create roles and change their permission grants.', TRUE),
    ('role-bindings:manage', 'Grant and revoke scoped roles.', TRUE),
    ('auth-mappings:read', 'Read external membership role mappings.', FALSE),
    ('auth-mappings:manage', 'Change external membership role mappings.', TRUE),
    ('sessions:read:self', 'Read the caller own sessions.', FALSE),
    ('sessions:revoke:self', 'Revoke the caller own sessions.', FALSE),
    ('sessions:read:any', 'Read sessions belonging to other members.', TRUE),
    ('sessions:revoke:any', 'Revoke sessions belonging to other members.', TRUE),
    ('audit:read', 'Read immutable security audit events.', TRUE),
    ('repositories:read', 'Read private repositories.', FALSE),
    ('repositories:create', 'Create repositories.', FALSE),
    ('repositories:settings:update', 'Update repository settings.', FALSE),
    ('repositories:visibility:update', 'Change repository publication audiences.', TRUE),
    ('repositories:access:manage', 'Manage repository-scoped access.', TRUE),
    ('repositories:delete', 'Delete repositories.', TRUE),
    ('workflows:read', 'Read workflow definitions.', FALSE),
    ('workflows:manage', 'Create and change workflow definitions.', FALSE),
    ('runs:read', 'Read workflow runs.', FALSE),
    ('runs:dispatch', 'Dispatch workflow runs.', FALSE),
    ('runs:cancel', 'Cancel workflow runs.', FALSE),
    ('runs:rerun', 'Rerun workflow runs.', FALSE),
    ('jobs:read', 'Read jobs and attempts.', FALSE),
    ('logs:read', 'Read private job logs.', FALSE),
    ('artifacts:read', 'Read private artifact metadata.', FALSE),
    ('artifacts:download', 'Download private artifacts.', FALSE),
    ('artifacts:delete', 'Delete artifacts.', FALSE),
    ('caches:read', 'Read cache metadata.', FALSE),
    ('caches:delete', 'Delete caches.', FALSE),
    ('secrets:metadata:read', 'Read secret metadata without values.', TRUE),
    ('secrets:create', 'Create secret values without readback.', TRUE),
    ('secrets:update', 'Replace secret values without readback.', TRUE),
    ('secrets:delete', 'Delete secrets.', TRUE),
    ('secrets:policy:manage', 'Manage secret access policy.', TRUE),
    ('secret-providers:read', 'Read redacted secret-provider configuration.', TRUE),
    ('secret-providers:manage', 'Manage secret providers.', TRUE),
    ('secret-keys:rotate', 'Rotate secret encryption keys.', TRUE),
    ('environments:read', 'Read environment configuration.', FALSE),
    ('environments:manage', 'Manage environments and protection rules.', TRUE),
    ('environments:approve', 'Approve protected environment use.', TRUE),
    ('runners:read', 'Read runners and runner groups.', FALSE),
    ('runners:manage', 'Change runner lifecycle state.', TRUE),
    ('runners:enroll', 'Enroll new runners.', TRUE),
    ('runner-groups:read', 'Read runner groups and routing policy.', FALSE),
    ('runner-groups:manage', 'Manage runner groups and routing policy.', TRUE);

CREATE TABLE rbac_roles (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id UUID NOT NULL,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role_kind TEXT NOT NULL DEFAULT 'custom',
    immutable BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 1,
    created_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT rbac_roles_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT rbac_roles_tenant_name_unique UNIQUE (tenant_id, name),
    CONSTRAINT rbac_roles_name_shape CHECK (
        octet_length(name) BETWEEN 1 AND 128
        AND name ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT rbac_roles_display_name_shape CHECK (
        octet_length(display_name) BETWEEN 1 AND 255
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT rbac_roles_kind CHECK (role_kind IN ('built_in', 'custom')),
    CONSTRAINT rbac_roles_immutability_shape CHECK (
        (role_kind = 'built_in' AND immutable)
        OR role_kind = 'custom'
    ),
    CONSTRAINT rbac_roles_revision_positive CHECK (revision > 0),
    CONSTRAINT rbac_roles_time_monotonic CHECK (updated_at_ms >= created_at_ms),
    CONSTRAINT rbac_roles_creator_membership
        FOREIGN KEY (tenant_id, created_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE TABLE rbac_role_permissions (
    tenant_id TEXT NOT NULL,
    role_id UUID NOT NULL,
    permission_name TEXT NOT NULL REFERENCES rbac_permissions(name) ON DELETE RESTRICT,
    granted_by_principal_id UUID,
    granted_at_ms BIGINT NOT NULL,
    CONSTRAINT rbac_role_permissions_primary_key PRIMARY KEY (
        tenant_id, role_id, permission_name
    ),
    CONSTRAINT rbac_role_permissions_role
        FOREIGN KEY (tenant_id, role_id)
        REFERENCES rbac_roles(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT rbac_role_permissions_grantor_membership
        FOREIGN KEY (tenant_id, granted_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

-- A binding grants exactly one role and never expresses a deny. Scope columns
-- are explicit so the database can enforce the complete tenant/resource pair.
CREATE TABLE rbac_role_bindings (
    tenant_id TEXT NOT NULL,
    id UUID NOT NULL,
    principal_id UUID NOT NULL,
    role_id UUID NOT NULL,
    scope_kind TEXT NOT NULL,
    repository_id UUID,
    runner_group_id UUID,
    assignment_source TEXT NOT NULL DEFAULT 'manual',
    status TEXT NOT NULL DEFAULT 'active',
    created_by_principal_id UUID,
    revoked_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    valid_until_ms BIGINT,
    revoked_at_ms BIGINT,
    revocation_reason TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT rbac_role_bindings_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT rbac_role_bindings_principal_membership
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT rbac_role_bindings_role
        FOREIGN KEY (tenant_id, role_id)
        REFERENCES rbac_roles(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT rbac_role_bindings_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT rbac_role_bindings_runner_group
        FOREIGN KEY (tenant_id, runner_group_id)
        REFERENCES runner_groups(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT rbac_role_bindings_creator_membership
        FOREIGN KEY (tenant_id, created_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT rbac_role_bindings_revoker_membership
        FOREIGN KEY (tenant_id, revoked_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT rbac_role_bindings_scope_kind CHECK (
        scope_kind IN ('tenant', 'repository', 'runner_group')
    ),
    CONSTRAINT rbac_role_bindings_scope_shape CHECK ((
        (
            scope_kind = 'tenant'
            AND repository_id IS NULL
            AND runner_group_id IS NULL
        ) OR (
            scope_kind = 'repository'
            AND repository_id IS NOT NULL
            AND runner_group_id IS NULL
        ) OR (
            scope_kind = 'runner_group'
            AND repository_id IS NULL
            AND runner_group_id IS NOT NULL
        )
    ) IS TRUE),
    CONSTRAINT rbac_role_bindings_source CHECK (
        assignment_source IN ('manual', 'bootstrap', 'recovery')
    ),
    CONSTRAINT rbac_role_bindings_status CHECK (status IN ('active', 'revoked')),
    CONSTRAINT rbac_role_bindings_lifetime CHECK (
        valid_until_ms IS NULL OR valid_until_ms > created_at_ms
    ),
    CONSTRAINT rbac_role_bindings_revocation_shape CHECK ((
        (
            status = 'active'
            AND revoked_by_principal_id IS NULL
            AND revoked_at_ms IS NULL
            AND revocation_reason IS NULL
        ) OR (
            status = 'revoked'
            AND revoked_at_ms >= created_at_ms
            AND octet_length(revocation_reason) BETWEEN 1 AND 1024
            AND revocation_reason !~ '[[:cntrl:]]'
        )
    ) IS TRUE),
    CONSTRAINT rbac_role_bindings_revision_positive CHECK (revision > 0)
);

CREATE UNIQUE INDEX rbac_role_bindings_active_tenant_grant
    ON rbac_role_bindings (tenant_id, principal_id, role_id)
    WHERE status = 'active' AND scope_kind = 'tenant';

CREATE UNIQUE INDEX rbac_role_bindings_active_repository_grant
    ON rbac_role_bindings (tenant_id, principal_id, role_id, repository_id)
    WHERE status = 'active' AND scope_kind = 'repository';

CREATE UNIQUE INDEX rbac_role_bindings_active_runner_group_grant
    ON rbac_role_bindings (tenant_id, principal_id, role_id, runner_group_id)
    WHERE status = 'active' AND scope_kind = 'runner_group';

CREATE INDEX rbac_role_bindings_effective_principal
    ON rbac_role_bindings (tenant_id, principal_id, scope_kind, valid_until_ms)
    WHERE status = 'active';

-- GitHub display names can change and are never identity. Numeric organization
-- and team IDs are the only membership-to-role mapping keys.
CREATE TABLE github_role_mappings (
    tenant_id TEXT NOT NULL,
    id UUID NOT NULL,
    provider_id TEXT NOT NULL DEFAULT 'github',
    organization_id BIGINT NOT NULL,
    organization_login TEXT NOT NULL,
    team_id BIGINT,
    team_slug TEXT,
    role_id UUID NOT NULL,
    scope_kind TEXT NOT NULL,
    repository_id UUID,
    runner_group_id UUID,
    status TEXT NOT NULL DEFAULT 'active',
    created_by_principal_id UUID,
    disabled_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    disabled_at_ms BIGINT,
    revision BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT github_role_mappings_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT github_role_mappings_provider CHECK (provider_id = 'github'),
    CONSTRAINT github_role_mappings_organization_id_positive CHECK (organization_id > 0),
    CONSTRAINT github_role_mappings_organization_login_shape CHECK (
        octet_length(organization_login) BETWEEN 1 AND 255
        AND organization_login !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT github_role_mappings_membership_shape CHECK ((
        (
            team_id IS NULL
            AND team_slug IS NULL
        ) OR (
            team_id > 0
            AND octet_length(team_slug) BETWEEN 1 AND 255
            AND team_slug !~ '[[:space:][:cntrl:]]'
        )
    ) IS TRUE),
    CONSTRAINT github_role_mappings_role
        FOREIGN KEY (tenant_id, role_id)
        REFERENCES rbac_roles(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_role_mappings_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_role_mappings_runner_group
        FOREIGN KEY (tenant_id, runner_group_id)
        REFERENCES runner_groups(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_role_mappings_creator_membership
        FOREIGN KEY (tenant_id, created_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT github_role_mappings_disabler_membership
        FOREIGN KEY (tenant_id, disabled_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT github_role_mappings_scope_kind CHECK (
        scope_kind IN ('tenant', 'repository', 'runner_group')
    ),
    CONSTRAINT github_role_mappings_scope_shape CHECK ((
        (
            scope_kind = 'tenant'
            AND repository_id IS NULL
            AND runner_group_id IS NULL
        ) OR (
            scope_kind = 'repository'
            AND repository_id IS NOT NULL
            AND runner_group_id IS NULL
        ) OR (
            scope_kind = 'runner_group'
            AND repository_id IS NULL
            AND runner_group_id IS NOT NULL
        )
    ) IS TRUE),
    CONSTRAINT github_role_mappings_status CHECK (status IN ('active', 'disabled')),
    CONSTRAINT github_role_mappings_status_shape CHECK ((
        (
            status = 'active'
            AND disabled_by_principal_id IS NULL
            AND disabled_at_ms IS NULL
        ) OR (
            status = 'disabled'
            AND disabled_at_ms >= created_at_ms
        )
    ) IS TRUE),
    CONSTRAINT github_role_mappings_time_monotonic CHECK (updated_at_ms >= created_at_ms),
    CONSTRAINT github_role_mappings_revision_positive CHECK (revision > 0)
);

CREATE UNIQUE INDEX github_role_mappings_active_organization_tenant
    ON github_role_mappings (tenant_id, provider_id, organization_id, role_id)
    WHERE status = 'active' AND team_id IS NULL AND scope_kind = 'tenant';

CREATE UNIQUE INDEX github_role_mappings_active_team_tenant
    ON github_role_mappings (tenant_id, provider_id, organization_id, team_id, role_id)
    WHERE status = 'active' AND team_id IS NOT NULL AND scope_kind = 'tenant';

CREATE UNIQUE INDEX github_role_mappings_active_organization_repository
    ON github_role_mappings (
        tenant_id, provider_id, organization_id, role_id, repository_id
    ) WHERE status = 'active' AND team_id IS NULL AND scope_kind = 'repository';

CREATE UNIQUE INDEX github_role_mappings_active_team_repository
    ON github_role_mappings (
        tenant_id, provider_id, organization_id, team_id, role_id, repository_id
    ) WHERE status = 'active' AND team_id IS NOT NULL AND scope_kind = 'repository';

CREATE UNIQUE INDEX github_role_mappings_active_organization_runner_group
    ON github_role_mappings (
        tenant_id, provider_id, organization_id, role_id, runner_group_id
    ) WHERE status = 'active' AND team_id IS NULL AND scope_kind = 'runner_group';

CREATE UNIQUE INDEX github_role_mappings_active_team_runner_group
    ON github_role_mappings (
        tenant_id, provider_id, organization_id, team_id, role_id, runner_group_id
    ) WHERE status = 'active' AND team_id IS NOT NULL AND scope_kind = 'runner_group';

-- A session records the exact authorization generation of its principal's
-- tenant membership. Authorization-affecting writes bump that generation in
-- the same transaction, so sessions never trust login-time role snapshots.
CREATE FUNCTION automata_membership_status_authorization_revision()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.authorization_revision < OLD.authorization_revision THEN
        RAISE EXCEPTION 'membership authorization revision cannot decrease';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.authorization_revision := GREATEST(
            NEW.authorization_revision,
            OLD.authorization_revision + 1
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tenant_human_memberships_authorization_revision
BEFORE UPDATE ON tenant_human_memberships
FOR EACH ROW EXECUTE FUNCTION automata_membership_status_authorization_revision();

CREATE FUNCTION automata_role_binding_authorization_revision()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        UPDATE tenant_human_memberships
        SET authorization_revision = authorization_revision + 1
        WHERE tenant_id = NEW.tenant_id AND principal_id = NEW.principal_id;
    END IF;
    IF TG_OP <> 'INSERT' AND (
        TG_OP = 'DELETE'
        OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.principal_id IS DISTINCT FROM NEW.principal_id
    ) THEN
        UPDATE tenant_human_memberships
        SET authorization_revision = authorization_revision + 1
        WHERE tenant_id = OLD.tenant_id AND principal_id = OLD.principal_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER rbac_role_bindings_authorization_revision
AFTER INSERT OR UPDATE OR DELETE ON rbac_role_bindings
FOR EACH ROW EXECUTE FUNCTION automata_role_binding_authorization_revision();

CREATE FUNCTION automata_role_permission_authorization_revision()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        UPDATE tenant_human_memberships AS membership
        SET authorization_revision = membership.authorization_revision + 1
        WHERE membership.tenant_id = NEW.tenant_id
          AND EXISTS (
              SELECT 1 FROM rbac_role_bindings AS binding
              WHERE binding.tenant_id = NEW.tenant_id
                AND binding.principal_id = membership.principal_id
                AND binding.role_id = NEW.role_id
                AND binding.status = 'active'
          );
    END IF;
    IF TG_OP <> 'INSERT' AND (
        TG_OP = 'DELETE'
        OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.role_id IS DISTINCT FROM NEW.role_id
    ) THEN
        UPDATE tenant_human_memberships AS membership
        SET authorization_revision = membership.authorization_revision + 1
        WHERE membership.tenant_id = OLD.tenant_id
          AND EXISTS (
              SELECT 1 FROM rbac_role_bindings AS binding
              WHERE binding.tenant_id = OLD.tenant_id
                AND binding.principal_id = membership.principal_id
                AND binding.role_id = OLD.role_id
                AND binding.status = 'active'
          );
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER rbac_role_permissions_authorization_revision
AFTER INSERT OR UPDATE OR DELETE ON rbac_role_permissions
FOR EACH ROW EXECUTE FUNCTION automata_role_permission_authorization_revision();

-- External membership mappings can potentially affect any principal in their
-- tenant. Bumping the tenant's memberships is conservative and fail-closed;
-- current provider membership is still resolved independently on each request.
CREATE FUNCTION automata_github_mapping_authorization_revision()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        UPDATE tenant_human_memberships
        SET authorization_revision = authorization_revision + 1
        WHERE tenant_id = NEW.tenant_id;
    END IF;
    IF TG_OP <> 'INSERT'
       AND (TG_OP = 'DELETE' OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id) THEN
        UPDATE tenant_human_memberships
        SET authorization_revision = authorization_revision + 1
        WHERE tenant_id = OLD.tenant_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER github_role_mappings_authorization_revision
AFTER INSERT OR UPDATE OR DELETE ON github_role_mappings
FOR EACH ROW EXECUTE FUNCTION automata_github_mapping_authorization_revision();

CREATE TABLE github_membership_snapshots (
    tenant_id TEXT NOT NULL,
    id UUID NOT NULL,
    principal_id UUID NOT NULL,
    provider_id TEXT NOT NULL DEFAULT 'github',
    provider_subject TEXT NOT NULL,
    provider_token_version BIGINT NOT NULL,
    observed_at_ms BIGINT NOT NULL,
    valid_until_ms BIGINT NOT NULL,
    CONSTRAINT github_membership_snapshots_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT github_membership_snapshots_provider CHECK (provider_id = 'github'),
    CONSTRAINT github_membership_snapshots_token_version_positive CHECK (
        provider_token_version > 0
    ),
    CONSTRAINT github_membership_snapshots_validity CHECK (
        valid_until_ms > observed_at_ms
    ),
    CONSTRAINT github_membership_snapshots_membership
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT github_membership_snapshots_identity
        FOREIGN KEY (principal_id, provider_id, provider_subject)
        REFERENCES human_provider_identities(principal_id, provider_id, provider_subject)
        ON DELETE RESTRICT
);

CREATE INDEX github_membership_snapshots_current
    ON github_membership_snapshots (
        tenant_id, principal_id, provider_id, valid_until_ms DESC, observed_at_ms DESC
    );

CREATE TABLE github_organization_membership_observations (
    tenant_id TEXT NOT NULL,
    snapshot_id UUID NOT NULL,
    organization_id BIGINT NOT NULL,
    organization_login TEXT NOT NULL,
    membership_role TEXT NOT NULL,
    CONSTRAINT github_organization_membership_observations_primary_key PRIMARY KEY (
        tenant_id, snapshot_id, organization_id
    ),
    CONSTRAINT github_organization_membership_observations_snapshot
        FOREIGN KEY (tenant_id, snapshot_id)
        REFERENCES github_membership_snapshots(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT github_organization_membership_observations_id_positive CHECK (
        organization_id > 0
    ),
    CONSTRAINT github_organization_membership_observations_login_shape CHECK (
        octet_length(organization_login) BETWEEN 1 AND 255
        AND organization_login !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT github_organization_membership_observations_role CHECK (
        membership_role IN ('member', 'admin')
    )
);

CREATE TABLE github_team_membership_observations (
    tenant_id TEXT NOT NULL,
    snapshot_id UUID NOT NULL,
    organization_id BIGINT NOT NULL,
    team_id BIGINT NOT NULL,
    team_slug TEXT NOT NULL,
    CONSTRAINT github_team_membership_observations_primary_key PRIMARY KEY (
        tenant_id, snapshot_id, team_id
    ),
    CONSTRAINT github_team_membership_observations_organization
        FOREIGN KEY (tenant_id, snapshot_id, organization_id)
        REFERENCES github_organization_membership_observations(
            tenant_id, snapshot_id, organization_id
        ) ON DELETE CASCADE,
    CONSTRAINT github_team_membership_observations_id_positive CHECK (team_id > 0),
    CONSTRAINT github_team_membership_observations_slug_shape CHECK (
        octet_length(team_slug) BETWEEN 1 AND 255
        AND team_slug !~ '[[:space:][:cntrl:]]'
    )
);

CREATE TABLE security_audit_events (
    sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    occurred_at_ms BIGINT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_principal_id UUID,
    actor_session_id UUID,
    authorization_revision BIGINT,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT,
    request_id TEXT,
    CONSTRAINT security_audit_events_actor_membership
        FOREIGN KEY (tenant_id, actor_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT security_audit_events_actor_session
        FOREIGN KEY (tenant_id, actor_principal_id, actor_session_id)
        REFERENCES human_sessions(tenant_id, principal_id, id) ON DELETE RESTRICT,
    CONSTRAINT security_audit_events_actor_kind CHECK (
        actor_kind IN ('system', 'human')
    ),
    CONSTRAINT security_audit_events_actor_shape CHECK ((
        (
            actor_kind = 'system'
            AND actor_principal_id IS NULL
            AND actor_session_id IS NULL
            AND authorization_revision IS NULL
        ) OR (
            actor_kind = 'human'
            AND actor_principal_id IS NOT NULL
            AND (
                authorization_revision IS NULL
                OR authorization_revision > 0
            )
        )
    ) IS TRUE),
    CONSTRAINT security_audit_events_action_shape CHECK (
        octet_length(action) BETWEEN 1 AND 128
        AND action ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT security_audit_events_outcome CHECK (
        outcome IN ('succeeded', 'denied', 'failed')
    ),
    CONSTRAINT security_audit_events_resource_kind_shape CHECK (
        octet_length(resource_kind) BETWEEN 1 AND 128
        AND resource_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT security_audit_events_resource_id_shape CHECK (
        resource_id IS NULL OR (
            octet_length(resource_id) BETWEEN 1 AND 1024
            AND resource_id !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT security_audit_events_request_id_shape CHECK (
        request_id IS NULL OR (
            octet_length(request_id) BETWEEN 1 AND 255
            AND request_id !~ '[[:space:][:cntrl:]]'
        )
    )
);

CREATE INDEX security_audit_events_tenant_time
    ON security_audit_events (tenant_id, occurred_at_ms DESC, sequence DESC);

CREATE INDEX security_audit_events_actor_time
    ON security_audit_events (
        tenant_id, actor_principal_id, occurred_at_ms DESC, sequence DESC
    ) WHERE actor_principal_id IS NOT NULL;

CREATE FUNCTION automata_security_audit_events_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'Automata security audit events are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'security_audit_events_append_only';
END;
$automata$;

CREATE TRIGGER security_audit_events_append_only_rows
BEFORE UPDATE OR DELETE ON security_audit_events
FOR EACH ROW
EXECUTE FUNCTION automata_security_audit_events_append_only();

CREATE TRIGGER security_audit_events_append_only_truncate
BEFORE TRUNCATE ON security_audit_events
FOR EACH STATEMENT
EXECUTE FUNCTION automata_security_audit_events_append_only();

-- Dashboard, logs, and artifacts are independent audiences. Public logs and
-- artifacts retain an explicit safety gate; a repository preference alone can
-- never publish an attempt classified as secret-bearing.
CREATE TABLE repository_publication_policies (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    dashboard_audience TEXT NOT NULL DEFAULT 'private',
    log_audience TEXT NOT NULL DEFAULT 'private',
    artifact_audience TEXT NOT NULL DEFAULT 'private',
    revision BIGINT NOT NULL DEFAULT 1,
    updated_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT repository_publication_policies_primary_key PRIMARY KEY (
        tenant_id, repository_id
    ),
    CONSTRAINT repository_publication_policies_repository_unique UNIQUE (repository_id),
    CONSTRAINT repository_publication_policies_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT repository_publication_policies_updater_membership
        FOREIGN KEY (tenant_id, updated_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT repository_publication_policies_dashboard_audience CHECK (
        dashboard_audience IN ('private', 'authenticated', 'public')
    ),
    CONSTRAINT repository_publication_policies_log_audience CHECK (
        log_audience IN ('private', 'authenticated', 'public_if_safe')
    ),
    CONSTRAINT repository_publication_policies_artifact_audience CHECK (
        artifact_audience IN ('private', 'authenticated', 'public_if_safe')
    ),
    CONSTRAINT repository_publication_policies_revision_positive CHECK (revision > 0),
    CONSTRAINT repository_publication_policies_time_monotonic CHECK (
        updated_at_ms >= created_at_ms
    )
);

INSERT INTO repository_publication_policies (
    tenant_id, repository_id, dashboard_audience, log_audience,
    artifact_audience, revision, created_at_ms, updated_at_ms
)
SELECT
    tenant_id, id, 'private', 'private', 'private', 1,
    created_at_ms, updated_at_ms
FROM repositories;

CREATE FUNCTION automata_seed_repository_publication_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    INSERT INTO repository_publication_policies (
        tenant_id, repository_id, dashboard_audience, log_audience,
        artifact_audience, revision, created_at_ms, updated_at_ms
    ) VALUES (
        NEW.tenant_id, NEW.id, 'private', 'private', 'private', 1,
        NEW.created_at_ms, NEW.updated_at_ms
    );
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER repositories_seed_publication_policy
AFTER INSERT ON repositories
FOR EACH ROW
EXECUTE FUNCTION automata_seed_repository_publication_policy();
