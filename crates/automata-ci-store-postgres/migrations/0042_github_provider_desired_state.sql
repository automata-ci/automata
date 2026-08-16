CREATE TABLE github_provider_registry_lock (
    singleton boolean PRIMARY KEY DEFAULT true,
    CONSTRAINT github_provider_registry_lock_singleton CHECK (singleton)
);

INSERT INTO github_provider_registry_lock (singleton) VALUES (true);

CREATE TABLE github_provider_configuration_operations (
    authority_id text NOT NULL,
    operation_id uuid NOT NULL,
    shard_id text NOT NULL,
    revision bigint NOT NULL,
    request_digest bytea NOT NULL,
    applied_at_ms bigint NOT NULL,
    PRIMARY KEY (authority_id, operation_id),
    UNIQUE (revision),
    UNIQUE (authority_id, operation_id, shard_id, revision),
    CONSTRAINT github_provider_configuration_operations_authority_shape CHECK (
        octet_length(authority_id) BETWEEN 1 AND 255
        AND authority_id !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT github_provider_configuration_operations_shard_shape CHECK (
        octet_length(shard_id) BETWEEN 1 AND 63
        AND shard_id ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    ),
    CONSTRAINT github_provider_configuration_operations_revision_positive CHECK (revision > 0),
    CONSTRAINT github_provider_configuration_operations_digest_shape CHECK (octet_length(request_digest) = 32),
    CONSTRAINT github_provider_configuration_operations_time_nonnegative CHECK (applied_at_ms >= 0)
);

CREATE TABLE github_provider_configuration_current (
    singleton boolean PRIMARY KEY DEFAULT true,
    shard_id text NOT NULL,
    revision bigint NOT NULL UNIQUE,
    authority_id text NOT NULL,
    operation_id uuid NOT NULL,
    dashboard_url text NOT NULL,
    github_app_id bigint NOT NULL,
    github_app_client_id text NOT NULL,
    github_app_jwt_issuer_kind text NOT NULL,
    app_configuration_revision bigint NOT NULL,
    app_private_key_sha256 bytea NOT NULL,
    app_private_key_envelope_schema smallint NOT NULL,
    app_private_key_wrapping_key_id text NOT NULL,
    app_private_key_wrapped_data_key bytea NOT NULL,
    app_private_key_nonce bytea NOT NULL,
    app_private_key_ciphertext bytea NOT NULL,
    webhook_verifier_revision bigint NOT NULL,
    webhook_secret_sha256 bytea NOT NULL,
    webhook_secret_envelope_schema smallint NOT NULL,
    webhook_secret_wrapping_key_id text NOT NULL,
    webhook_secret_wrapped_data_key bytea NOT NULL,
    webhook_secret_nonce bytea NOT NULL,
    webhook_secret_ciphertext bytea NOT NULL,
    check_name text NOT NULL,
    runner_policy bytea NOT NULL,
    schedule_poll_millis bigint NOT NULL,
    schedule_discovery_claim_millis bigint NOT NULL,
    schedule_fire_claim_millis bigint NOT NULL,
    schedule_retry_millis bigint NOT NULL,
    schedule_staleness_millis bigint NOT NULL,
    schedule_maximum_manifests integer NOT NULL,
    schedule_maximum_fires_per_pass integer NOT NULL,
    applied_at_ms bigint NOT NULL,
    CONSTRAINT github_provider_configuration_current_singleton CHECK (singleton),
    CONSTRAINT github_provider_configuration_current_operation FOREIGN KEY (
        authority_id, operation_id, shard_id, revision
    ) REFERENCES github_provider_configuration_operations(
        authority_id, operation_id, shard_id, revision
    ) ON DELETE RESTRICT,
    CONSTRAINT github_provider_configuration_current_app_positive CHECK (
        github_app_id > 0 AND app_configuration_revision > 0 AND webhook_verifier_revision > 0
    ),
    CONSTRAINT github_provider_configuration_current_jwt_issuer CHECK (
        github_app_jwt_issuer_kind IN ('app_client_id', 'app_id')
    ),
    CONSTRAINT github_provider_configuration_current_digest_shape CHECK (
        octet_length(app_private_key_sha256) = 32 AND octet_length(webhook_secret_sha256) = 32
    ),
    CONSTRAINT github_provider_configuration_current_envelope_shape CHECK (
        app_private_key_envelope_schema > 0
        AND octet_length(app_private_key_wrapped_data_key) > 0
        AND octet_length(app_private_key_nonce) = 12
        AND octet_length(app_private_key_ciphertext) > 16
        AND webhook_secret_envelope_schema > 0
        AND octet_length(webhook_secret_wrapped_data_key) > 0
        AND octet_length(webhook_secret_nonce) = 12
        AND octet_length(webhook_secret_ciphertext) > 16
    ),
    CONSTRAINT github_provider_configuration_current_policy_shape CHECK (
        octet_length(runner_policy) BETWEEN 1 AND 65536
        AND schedule_poll_millis > 0
        AND schedule_discovery_claim_millis > 0
        AND schedule_fire_claim_millis > 0
        AND schedule_retry_millis > 0
        AND schedule_staleness_millis > 0
        AND schedule_maximum_manifests > 0
        AND schedule_maximum_fires_per_pass > 0
    ),
    CONSTRAINT github_provider_configuration_current_time_nonnegative CHECK (applied_at_ms >= 0)
);

CREATE TABLE workspace_github_repository_operations (
    authority_id text NOT NULL,
    operation_id uuid NOT NULL,
    shard_id text NOT NULL,
    workspace_id text NOT NULL,
    revision bigint NOT NULL,
    request_digest bytea NOT NULL,
    applied_at_ms bigint NOT NULL,
    PRIMARY KEY (authority_id, operation_id),
    UNIQUE (workspace_id, revision),
    UNIQUE (authority_id, operation_id, workspace_id, shard_id, revision),
    CONSTRAINT workspace_github_repository_operations_binding FOREIGN KEY (
        workspace_id, authority_id, shard_id
    ) REFERENCES workspace_management_bindings(workspace_id, authority_id, shard_id) ON DELETE RESTRICT,
    CONSTRAINT workspace_github_repository_operations_revision_positive CHECK (revision > 0),
    CONSTRAINT workspace_github_repository_operations_digest_shape CHECK (octet_length(request_digest) = 32),
    CONSTRAINT workspace_github_repository_operations_time_nonnegative CHECK (applied_at_ms >= 0)
);

CREATE TABLE workspace_github_repository_current (
    workspace_id text PRIMARY KEY,
    shard_id text NOT NULL,
    revision bigint NOT NULL,
    authority_id text NOT NULL,
    operation_id uuid NOT NULL,
    applied_at_ms bigint NOT NULL,
    UNIQUE (workspace_id, shard_id, revision),
    CONSTRAINT workspace_github_repository_current_operation FOREIGN KEY (
        authority_id, operation_id, workspace_id, shard_id, revision
    ) REFERENCES workspace_github_repository_operations(
        authority_id, operation_id, workspace_id, shard_id, revision
    ) ON DELETE RESTRICT,
    CONSTRAINT workspace_github_repository_current_time_nonnegative CHECK (applied_at_ms >= 0)
);

CREATE INDEX workspace_github_repository_current_shard_scan
    ON workspace_github_repository_current (shard_id, workspace_id);

CREATE TABLE workspace_github_repository_selections (
    workspace_id text NOT NULL,
    shard_id text NOT NULL,
    revision bigint NOT NULL,
    ordinal integer NOT NULL,
    provider_installation_id bigint NOT NULL,
    provider_repository_id bigint NOT NULL,
    provider_repository_owner_id bigint NOT NULL,
    repository_name text NOT NULL COLLATE "C",
    default_branch text NOT NULL COLLATE "C",
    repository_visibility text NOT NULL COLLATE "C",
    authority_profile text NOT NULL COLLATE "C",
    PRIMARY KEY (workspace_id, ordinal),
    UNIQUE (shard_id, provider_repository_id),
    CONSTRAINT workspace_github_repository_selections_current FOREIGN KEY (
        workspace_id, shard_id, revision
    ) REFERENCES workspace_github_repository_current(
        workspace_id, shard_id, revision
    ) ON DELETE CASCADE,
    CONSTRAINT workspace_github_repository_selections_ordinal_nonnegative CHECK (ordinal >= 0),
    CONSTRAINT workspace_github_repository_selections_ids_positive CHECK (
        provider_installation_id > 0
        AND provider_repository_id > 0
        AND provider_repository_owner_id > 0
    ),
    CONSTRAINT workspace_github_repository_selections_visibility CHECK (
        repository_visibility IN ('public', 'private')
    ),
    CONSTRAINT workspace_github_repository_selections_authority_profile CHECK (
        authority_profile IN ('standard', 'credential_free')
        AND NOT (repository_visibility = 'private' AND authority_profile = 'credential_free')
    )
);

CREATE UNIQUE INDEX workspace_github_repository_selections_name_ci
    ON workspace_github_repository_selections (shard_id, lower(repository_name));
