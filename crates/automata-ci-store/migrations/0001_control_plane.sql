CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT tenants_id_shape CHECK (
        octet_length(id) BETWEEN 1 AND 255
        AND id !~ '[[:cntrl:]]'
    ),
    CONSTRAINT tenants_display_name_nonempty CHECK (length(display_name) > 0)
);

CREATE TABLE repositories (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    scm_provider TEXT NOT NULL,
    provider_repository_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT repositories_provider_identity_unique
        UNIQUE (tenant_id, scm_provider, provider_repository_id),
    CONSTRAINT repositories_owner_nonempty CHECK (length(owner) > 0),
    CONSTRAINT repositories_name_nonempty CHECK (length(name) > 0)
);

CREATE UNIQUE INDEX repositories_provider_owner_name_unique
    ON repositories (tenant_id, scm_provider, lower(owner), lower(name));

CREATE TABLE workflow_definitions (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_definitions_path_nonempty CHECK (length(path) > 0),
    CONSTRAINT workflow_definitions_repository_path_unique
        UNIQUE (repository_id, path),
    CONSTRAINT workflow_definitions_repository_id_unique
        UNIQUE (repository_id, id)
);

CREATE TABLE workflow_snapshots (
    id UUID PRIMARY KEY,
    workflow_id UUID NOT NULL REFERENCES workflow_definitions(id) ON DELETE RESTRICT,
    source_digest BYTEA NOT NULL,
    source_object_key TEXT NOT NULL,
    frontend_schema SMALLINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_snapshots_sha256 CHECK (octet_length(source_digest) = 32),
    CONSTRAINT workflow_snapshots_digest_unique UNIQUE (workflow_id, source_digest),
    CONSTRAINT workflow_snapshots_id_workflow_unique UNIQUE (id, workflow_id),
    CONSTRAINT workflow_snapshots_object_key_nonempty CHECK (length(source_object_key) > 0),
    CONSTRAINT workflow_snapshots_schema_positive CHECK (frontend_schema > 0)
);

CREATE TABLE workflow_runs (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    workflow_id UUID NOT NULL,
    snapshot_id UUID NOT NULL REFERENCES workflow_snapshots(id) ON DELETE RESTRICT,
    run_number BIGINT NOT NULL,
    run_attempt INTEGER NOT NULL DEFAULT 1,
    event_name TEXT NOT NULL,
    event_object_key TEXT NOT NULL,
    head_sha BYTEA NOT NULL,
    status TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_runs_number_positive CHECK (run_number > 0),
    CONSTRAINT workflow_runs_attempt_positive CHECK (run_attempt > 0),
    CONSTRAINT workflow_runs_sha CHECK (octet_length(head_sha) IN (20, 32)),
    CONSTRAINT workflow_runs_status CHECK (
        status IN ('queued', 'in_progress', 'completed', 'cancelled')
    ),
    CONSTRAINT workflow_runs_workflow_matches_repository
        FOREIGN KEY (repository_id, workflow_id)
        REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_runs_snapshot_matches_workflow
        FOREIGN KEY (snapshot_id, workflow_id)
        REFERENCES workflow_snapshots(id, workflow_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_runs_number_attempt_unique
        UNIQUE (workflow_id, run_number, run_attempt),
    CONSTRAINT workflow_runs_repository_id_unique
        UNIQUE (repository_id, id)
);

CREATE TABLE jobs (
    id UUID PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    job_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    job_ir_digest BYTEA NOT NULL,
    job_ir_object_key TEXT NOT NULL,
    requirements JSONB NOT NULL,
    runner_group TEXT,
    labels TEXT[] NOT NULL DEFAULT '{}',
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT jobs_key_nonempty CHECK (length(job_key) > 0),
    CONSTRAINT jobs_ir_sha256 CHECK (octet_length(job_ir_digest) = 32),
    CONSTRAINT jobs_ir_object_key_nonempty CHECK (length(job_ir_object_key) > 0),
    CONSTRAINT jobs_run_key_unique UNIQUE (run_id, job_key)
);

CREATE TABLE runner_groups (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    routing_policy JSONB NOT NULL DEFAULT '{}',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT runner_groups_name_nonempty CHECK (length(name) > 0),
    CONSTRAINT runner_groups_normalized_unique UNIQUE (tenant_id, normalized_name),
    CONSTRAINT runner_groups_tenant_id_unique UNIQUE (tenant_id, id)
);

CREATE TABLE runners (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    group_id UUID,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    labels TEXT[] NOT NULL DEFAULT '{}',
    capabilities JSONB NOT NULL,
    slots INTEGER NOT NULL,
    status TEXT NOT NULL,
    generation BIGINT NOT NULL DEFAULT 1,
    last_seen_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT runners_slots_positive CHECK (slots > 0),
    CONSTRAINT runners_generation_positive CHECK (generation > 0),
    CONSTRAINT runners_status CHECK (status IN ('offline', 'online', 'draining', 'disabled')),
    CONSTRAINT runners_name_unique UNIQUE (tenant_id, normalized_name),
    CONSTRAINT runners_group_matches_tenant
        FOREIGN KEY (tenant_id, group_id)
        REFERENCES runner_groups(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE runner_sessions (
    id UUID PRIMARY KEY,
    runner_id UUID NOT NULL REFERENCES runners(id) ON DELETE CASCADE,
    protocol_version INTEGER NOT NULL,
    job_ir_schema INTEGER NOT NULL,
    capability_snapshot JSONB NOT NULL,
    connected_at_ms BIGINT NOT NULL,
    heartbeat_at_ms BIGINT NOT NULL,
    disconnected_at_ms BIGINT,
    CONSTRAINT runner_sessions_protocol_positive CHECK (protocol_version > 0),
    CONSTRAINT runner_sessions_job_ir_positive CHECK (job_ir_schema > 0)
);

CREATE INDEX runner_sessions_live_by_runner
    ON runner_sessions (runner_id, heartbeat_at_ms)
    WHERE disconnected_at_ms IS NULL;

CREATE TABLE job_attempts (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    attempt_number INTEGER NOT NULL,
    lifecycle TEXT NOT NULL,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    lease_id UUID,
    runner_id UUID REFERENCES runners(id) ON DELETE RESTRICT,
    lease_issued_at_ms BIGINT,
    lease_expires_at_ms BIGINT,
    lease_failures INTEGER NOT NULL DEFAULT 0,
    queued_at_ms BIGINT NOT NULL,
    changed_at_ms BIGINT NOT NULL,
    CONSTRAINT job_attempts_number_positive CHECK (attempt_number > 0),
    CONSTRAINT job_attempts_fence_nonnegative CHECK (fencing_token >= 0),
    CONSTRAINT job_attempts_failures_nonnegative CHECK (lease_failures >= 0),
    CONSTRAINT job_attempts_lifecycle CHECK (
        lifecycle IN (
            'queued', 'leased', 'preparing', 'running', 'cancelling', 'finalizing',
            'succeeded', 'failed', 'cancelled', 'timed_out', 'skipped', 'lost'
        )
    ),
    CONSTRAINT job_attempts_job_number_unique UNIQUE (job_id, attempt_number),
    CONSTRAINT job_attempts_lease_fields_consistent CHECK (
        (lease_id IS NULL AND runner_id IS NULL AND lease_issued_at_ms IS NULL AND lease_expires_at_ms IS NULL)
        OR
        (lease_id IS NOT NULL AND runner_id IS NOT NULL AND lease_issued_at_ms IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
    ),
    CONSTRAINT job_attempts_active_lease_consistent CHECK (
        (lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing'))
        = (lease_id IS NOT NULL)
    ),
    CONSTRAINT job_attempts_active_lease_fenced CHECK (
        lease_id IS NULL OR fencing_token > 0
    ),
    CONSTRAINT job_attempts_lease_interval CHECK (
        lease_id IS NULL OR lease_expires_at_ms > lease_issued_at_ms
    ),
    CONSTRAINT job_attempts_state_time_monotonic CHECK (
        changed_at_ms >= queued_at_ms
    ),
    CONSTRAINT job_attempts_active_observation_within_lease CHECK (
        lease_id IS NULL
        OR lease_expires_at_ms <= lease_issued_at_ms
        OR (
            changed_at_ms >= lease_issued_at_ms
            AND changed_at_ms < lease_expires_at_ms
        )
    )
);

CREATE UNIQUE INDEX job_attempts_active_lease_unique
    ON job_attempts (lease_id)
    WHERE lease_id IS NOT NULL;

CREATE INDEX job_attempts_queue_order
    ON job_attempts (queued_at_ms, id)
    WHERE lifecycle = 'queued';

CREATE INDEX job_attempts_expiring_leases
    ON job_attempts (lease_expires_at_ms, id)
    WHERE lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing');

CREATE TABLE concurrency_groups (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    normalized_key TEXT NOT NULL,
    display_key TEXT NOT NULL,
    running_run_id UUID,
    pending_run_id UUID,
    generation BIGINT NOT NULL DEFAULT 1,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT concurrency_groups_primary_key PRIMARY KEY (repository_id, normalized_key),
    CONSTRAINT concurrency_groups_key_nonempty CHECK (length(normalized_key) > 0),
    CONSTRAINT concurrency_groups_generation_positive CHECK (generation > 0),
    CONSTRAINT concurrency_groups_distinct_slots CHECK (
        running_run_id IS NULL OR pending_run_id IS NULL OR running_run_id <> pending_run_id
    ),
    CONSTRAINT concurrency_groups_running_run_matches_repository
        FOREIGN KEY (repository_id, running_run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT concurrency_groups_pending_run_matches_repository
        FOREIGN KEY (repository_id, pending_run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT
);
