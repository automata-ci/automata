CREATE TABLE provider_instance_revisions (
    instance_id UUID NOT NULL,
    revision BIGINT NOT NULL,
    provider_type TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    web_origin TEXT NOT NULL,
    api_origin TEXT NOT NULL,
    configuration_schema SMALLINT NOT NULL,
    configuration_bytes BYTEA NOT NULL,
    configuration_digest BYTEA NOT NULL,
    capability_digest BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    activated_at_ms BIGINT,
    retired_at_ms BIGINT,
    manifest_digest BYTEA NOT NULL,
    PRIMARY KEY (instance_id, revision),
    UNIQUE (
        instance_id, revision, configuration_digest, capability_digest
    ),
    CHECK (revision > 0),
    CHECK (octet_length(provider_type) BETWEEN 1 AND 64),
    CHECK (provider_type ~ '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$'),
    CHECK (lifecycle_state IN ('disabled', 'active', 'retired')),
    CHECK (octet_length(web_origin) BETWEEN 1 AND 2048),
    CHECK (octet_length(api_origin) BETWEEN 1 AND 2048),
    CHECK (configuration_schema > 0),
    CHECK (octet_length(configuration_bytes) BETWEEN 1 AND 262144),
    CHECK (octet_length(configuration_digest) = 32),
    CHECK (octet_length(capability_digest) = 32),
    CHECK (octet_length(manifest_digest) = 32),
    CHECK (created_at_ms >= 0),
    CHECK (activated_at_ms IS NULL OR activated_at_ms >= created_at_ms),
    CHECK (
        retired_at_ms IS NULL
        OR retired_at_ms >= COALESCE(activated_at_ms, created_at_ms)
    ),
    CHECK (
        (lifecycle_state = 'active' AND activated_at_ms IS NOT NULL AND retired_at_ms IS NULL)
        OR (lifecycle_state = 'retired' AND retired_at_ms IS NOT NULL)
        OR (lifecycle_state = 'disabled' AND retired_at_ms IS NULL)
    )
);

CREATE TABLE provider_instance_secret_bindings (
    instance_id UUID NOT NULL,
    revision BIGINT NOT NULL,
    secret_name TEXT NOT NULL,
    secret_generation BIGINT NOT NULL,
    plaintext_digest BYTEA NOT NULL,
    envelope_schema SMALLINT NOT NULL,
    wrapping_key_id TEXT NOT NULL,
    wrapped_data_key BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    PRIMARY KEY (instance_id, revision, secret_name),
    FOREIGN KEY (instance_id, revision)
        REFERENCES provider_instance_revisions (instance_id, revision)
        ON DELETE RESTRICT,
    CHECK (octet_length(secret_name) BETWEEN 1 AND 64),
    CHECK (secret_name ~ '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$'),
    CHECK (secret_generation > 0),
    CHECK (octet_length(plaintext_digest) = 32),
    CHECK (envelope_schema > 0),
    CHECK (octet_length(wrapping_key_id) BETWEEN 1 AND 64),
    CHECK (octet_length(wrapped_data_key) BETWEEN 1 AND 65536),
    CHECK (octet_length(nonce) = 12),
    CHECK (octet_length(ciphertext) BETWEEN 17 AND 16777232)
);

CREATE TABLE provider_instance_current (
    instance_id UUID PRIMARY KEY,
    revision BIGINT NOT NULL,
    FOREIGN KEY (instance_id, revision)
        REFERENCES provider_instance_revisions (instance_id, revision)
        ON DELETE RESTRICT
);

CREATE TABLE provider_connection_revisions (
    connection_id UUID NOT NULL,
    revision BIGINT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    provider_instance_id UUID NOT NULL,
    external_repository_id TEXT NOT NULL,
    provider_revision BIGINT NOT NULL,
    provider_configuration_digest BYTEA NOT NULL,
    capability_digest BYTEA NOT NULL,
    repository_visibility TEXT NOT NULL,
    default_branch TEXT NOT NULL,
    workflow_source_kind TEXT NOT NULL,
    workflow_source_path TEXT NOT NULL,
    runner_policy_schema SMALLINT NOT NULL,
    runner_policy_digest BYTEA NOT NULL,
    archive_compressed_bytes BIGINT NOT NULL,
    archive_expanded_bytes BIGINT NOT NULL,
    archive_entries BIGINT NOT NULL,
    archive_entry_path_bytes BIGINT NOT NULL,
    archive_workflows BIGINT NOT NULL,
    workflow_bytes BIGINT NOT NULL,
    adapter_policy_schema SMALLINT NOT NULL,
    adapter_policy_bytes BYTEA NOT NULL,
    adapter_policy_digest BYTEA NOT NULL,
    configuration_digest BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    activated_at_ms BIGINT,
    retired_at_ms BIGINT,
    manifest_digest BYTEA NOT NULL,
    PRIMARY KEY (connection_id, revision),
    FOREIGN KEY (workspace_id) REFERENCES tenants (id) ON DELETE RESTRICT,
    FOREIGN KEY (
        provider_instance_id, provider_revision,
        provider_configuration_digest, capability_digest
    ) REFERENCES provider_instance_revisions (
        instance_id, revision, configuration_digest, capability_digest
    ) ON DELETE RESTRICT,
    CHECK (revision > 0),
    CHECK (lifecycle_state IN ('disabled', 'active', 'retired')),
    CHECK (octet_length(external_repository_id) BETWEEN 1 AND 512),
    CHECK (repository_visibility IN ('public', 'internal', 'private')),
    CHECK (octet_length(default_branch) BETWEEN 1 AND 255),
    CHECK (workflow_source_kind IN ('directory', 'file')),
    CHECK (octet_length(workflow_source_path) BETWEEN 1 AND 1024),
    CHECK (runner_policy_schema > 0),
    CHECK (octet_length(runner_policy_digest) = 32),
    CHECK (archive_compressed_bytes BETWEEN 1 AND 4294967296),
    CHECK (
        archive_expanded_bytes BETWEEN archive_compressed_bytes AND 17179869184
    ),
    CHECK (archive_entries BETWEEN 1 AND 1000000),
    CHECK (archive_entry_path_bytes BETWEEN 1 AND 16384),
    CHECK (archive_workflows BETWEEN 1 AND 4096),
    CHECK (archive_workflows <= archive_entries),
    CHECK (workflow_bytes BETWEEN 1 AND 4194304),
    CHECK (workflow_bytes <= archive_expanded_bytes),
    CHECK (adapter_policy_schema > 0),
    CHECK (octet_length(adapter_policy_bytes) BETWEEN 1 AND 65536),
    CHECK (octet_length(adapter_policy_digest) = 32),
    CHECK (octet_length(configuration_digest) = 32),
    CHECK (octet_length(manifest_digest) = 32),
    CHECK (created_at_ms >= 0),
    CHECK (activated_at_ms IS NULL OR activated_at_ms >= created_at_ms),
    CHECK (
        retired_at_ms IS NULL
        OR retired_at_ms >= COALESCE(activated_at_ms, created_at_ms)
    ),
    CHECK (
        (lifecycle_state = 'active' AND activated_at_ms IS NOT NULL AND retired_at_ms IS NULL)
        OR (lifecycle_state = 'retired' AND retired_at_ms IS NOT NULL)
        OR (lifecycle_state = 'disabled' AND retired_at_ms IS NULL)
    )
);

CREATE TABLE provider_connection_current (
    connection_id UUID PRIMARY KEY,
    revision BIGINT NOT NULL,
    FOREIGN KEY (connection_id, revision)
        REFERENCES provider_connection_revisions (connection_id, revision)
        ON DELETE RESTRICT
);

CREATE INDEX provider_connections_by_workspace
    ON provider_connection_revisions (workspace_id, connection_id, revision DESC);

CREATE INDEX provider_connections_by_repository
    ON provider_connection_revisions (
        provider_instance_id, external_repository_id, revision DESC
    );
