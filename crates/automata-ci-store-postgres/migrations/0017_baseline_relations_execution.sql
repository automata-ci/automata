CREATE TABLE attempt_cancellation_intents (
    attempt_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    requested_by text NOT NULL,
    reason text,
    requested_at_ms bigint NOT NULL,
    acknowledged_at_ms bigint,
    delivery_session_id uuid,
    delivery_command_sequence bigint,
    CONSTRAINT attempt_cancellation_ack_monotonic CHECK (((acknowledged_at_ms IS NULL) OR (acknowledged_at_ms >= requested_at_ms))),
    CONSTRAINT attempt_cancellation_actor_shape CHECK ((((octet_length(requested_by) >= 1) AND (octet_length(requested_by) <= 255)) AND (requested_by !~ '[[:cntrl:]]'::text))),
    CONSTRAINT attempt_cancellation_delivery_complete CHECK ((((delivery_session_id IS NULL) AND (delivery_command_sequence IS NULL)) OR ((delivery_session_id IS NOT NULL) AND (delivery_command_sequence IS NOT NULL)))),
    CONSTRAINT attempt_cancellation_reason_shape CHECK (((reason IS NULL) OR (((octet_length(reason) >= 1) AND (octet_length(reason) <= 1024)) AND (reason !~ '[[:cntrl:]]'::text))))
);

CREATE TABLE attempt_log_segments (
    stream_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    first_sequence bigint NOT NULL,
    last_sequence bigint NOT NULL,
    object_key text NOT NULL,
    object_digest bytea NOT NULL,
    encoded_size_bytes bigint NOT NULL,
    uncompressed_size_bytes bigint NOT NULL,
    stored_at_ms bigint NOT NULL,
    end_of_stream boolean DEFAULT false NOT NULL,
    CONSTRAINT attempt_log_segments_encoded_size CHECK (((encoded_size_bytes >= 1) AND (encoded_size_bytes <= 67108864))),
    CONSTRAINT attempt_log_segments_object_key_shape CHECK ((((octet_length(object_key) >= 1) AND (octet_length(object_key) <= 1024)) AND (object_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT attempt_log_segments_sequence_range CHECK (((first_sequence >= 0) AND (last_sequence >= first_sequence))),
    CONSTRAINT attempt_log_segments_sha256 CHECK ((octet_length(object_digest) = 32)),
    CONSTRAINT attempt_log_segments_uncompressed_size CHECK (((uncompressed_size_bytes >= 1) AND (uncompressed_size_bytes <= 268435456)))
);

CREATE TABLE attempt_log_streams (
    id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    runner_session_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_epoch bigint NOT NULL,
    runner_generation bigint NOT NULL,
    runner_slot integer NOT NULL,
    lease_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    log_schema integer NOT NULL,
    opened_at_ms bigint NOT NULL,
    closed_at_ms bigint,
    secret_exposure_class text DEFAULT 'readable_secret'::text NOT NULL,
    raw_log_disposition text DEFAULT 'persist'::text NOT NULL,
    requested_visibility text DEFAULT 'private'::text NOT NULL,
    effective_visibility text DEFAULT 'private'::text NOT NULL,
    output_safety_reason text DEFAULT 'repository_policy'::text NOT NULL,
    output_safety_schema integer DEFAULT 1 NOT NULL,
    CONSTRAINT attempt_log_streams_close_monotonic CHECK (((closed_at_ms IS NULL) OR (closed_at_ms >= opened_at_ms))),
    CONSTRAINT attempt_log_streams_exposure_safety CHECK (((output_safety_schema = 1) AND (raw_log_disposition = 'persist'::text) AND ((secret_exposure_class <> 'readable_secret'::text) OR (effective_visibility = 'private'::text)))),
    CONSTRAINT attempt_log_streams_fence_positive CHECK ((fencing_token > 0)),
    CONSTRAINT attempt_log_streams_output_safety_reason_code CHECK ((output_safety_reason = ANY (ARRAY['repository_policy'::text, 'secret_exposure'::text]))),
    CONSTRAINT attempt_log_streams_output_safety_schema CHECK ((output_safety_schema = 1)),
    CONSTRAINT attempt_log_streams_raw_log_disposition CHECK ((raw_log_disposition = 'persist'::text)),
    CONSTRAINT attempt_log_streams_schema_range CHECK (((log_schema >= 1) AND (log_schema <= 65535))),
    CONSTRAINT attempt_log_streams_secret_exposure_class CHECK ((secret_exposure_class = ANY (ARRAY['secretless'::text, 'capability_only'::text, 'readable_secret'::text]))),
    CONSTRAINT attempt_log_streams_slot_range CHECK (((runner_slot >= 1) AND (runner_slot <= 65535))),
    CONSTRAINT attempt_log_streams_visibility CHECK (((requested_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text])) AND (effective_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text])))),
    CONSTRAINT attempt_log_streams_visibility_cap CHECK (((effective_visibility = 'private'::text) OR ((effective_visibility = 'authenticated'::text) AND (requested_visibility = ANY (ARRAY['authenticated'::text, 'public'::text]))) OR ((effective_visibility = 'public'::text) AND (requested_visibility = 'public'::text))))
);

CREATE TABLE attempt_terminal_results (
    attempt_id uuid NOT NULL,
    runner_session_id uuid,
    operation_id uuid,
    runner_id uuid,
    runner_session_epoch bigint,
    runner_generation bigint,
    runner_slot integer,
    lease_id uuid,
    fencing_token bigint,
    result_schema integer,
    result_size_bytes bigint,
    result_digest bytea,
    result_object_key text,
    conclusion text NOT NULL,
    completed_at_ms bigint NOT NULL,
    committed_at_ms bigint NOT NULL,
    logical_workflow_logical_job_id uuid,
    logical_workflow_terminal_ordinal bigint,
    terminal_authority text NOT NULL,
    server_cancellation_operation_id uuid,
    server_cancellation_digest bytea,
    CONSTRAINT attempt_terminal_results_conclusion CHECK ((conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text]))),
    CONSTRAINT attempt_terminal_results_fence_positive CHECK ((fencing_token > 0)),
    CONSTRAINT attempt_terminal_results_object_key_shape CHECK ((((octet_length(result_object_key) >= 1) AND (octet_length(result_object_key) <= 1024)) AND (result_object_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT attempt_terminal_results_schema_range CHECK (((result_schema >= 1) AND (result_schema <= 65535))),
    CONSTRAINT attempt_terminal_results_server_cancellation_digest_sha256 CHECK (((server_cancellation_digest IS NULL) OR (octet_length(server_cancellation_digest) = 32))),
    CONSTRAINT attempt_terminal_results_sha256 CHECK ((octet_length(result_digest) = 32)),
    CONSTRAINT attempt_terminal_results_size_range CHECK (((result_size_bytes >= 1) AND (result_size_bytes <= 16777216))),
    CONSTRAINT attempt_terminal_results_slot_range CHECK (((runner_slot >= 1) AND (runner_slot <= 65535))),
    CONSTRAINT attempt_terminal_results_terminal_authority_shape CHECK (((((terminal_authority = 'runner'::text) AND (runner_session_id IS NOT NULL) AND (operation_id IS NOT NULL) AND (runner_id IS NOT NULL) AND (runner_session_epoch IS NOT NULL) AND (runner_generation IS NOT NULL) AND (runner_slot IS NOT NULL) AND (lease_id IS NOT NULL) AND (fencing_token IS NOT NULL) AND (result_schema IS NOT NULL) AND (result_size_bytes IS NOT NULL) AND (result_digest IS NOT NULL) AND (result_object_key IS NOT NULL) AND (server_cancellation_operation_id IS NULL) AND (server_cancellation_digest IS NULL)) OR ((terminal_authority = 'server_cancellation'::text) AND (runner_session_id IS NULL) AND (operation_id IS NULL) AND (runner_id IS NULL) AND (runner_session_epoch IS NULL) AND (runner_generation IS NULL) AND (runner_slot IS NULL) AND (lease_id IS NULL) AND (fencing_token IS NULL) AND (result_schema IS NULL) AND (result_size_bytes IS NULL) AND (result_digest IS NULL) AND (result_object_key IS NULL) AND (server_cancellation_operation_id IS NOT NULL) AND (server_cancellation_operation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (server_cancellation_digest IS NOT NULL) AND (conclusion = 'cancelled'::text))) IS TRUE)),
    CONSTRAINT attempt_terminal_results_time_monotonic CHECK ((committed_at_ms >= completed_at_ms)),
    CONSTRAINT attempt_terminal_results_logical_workflow_order_shape CHECK (((((logical_workflow_logical_job_id IS NULL) AND (logical_workflow_terminal_ordinal IS NULL)) OR ((logical_workflow_logical_job_id IS NOT NULL) AND (logical_workflow_terminal_ordinal > 0))) IS TRUE))
);

CREATE TABLE automata_cluster_compatibility (
    singleton boolean DEFAULT true NOT NULL,
    minimum_admission_epoch integer NOT NULL,
    job_ir_schema integer NOT NULL,
    runner_requirements_schema integer CONSTRAINT automata_cluster_compatibil_runner_requirements_schema_not_null NOT NULL,
    CONSTRAINT automata_cluster_compatibility_job_ir_current CHECK (((minimum_admission_epoch = 1) AND (job_ir_schema = 1) AND (runner_requirements_schema = 1))),
    CONSTRAINT automata_cluster_compatibility_singleton CHECK (singleton)
);

CREATE TABLE concurrency_group_pending_runs (
    repository_id uuid NOT NULL,
    normalized_key text NOT NULL,
    run_id uuid NOT NULL,
    queue_sequence bigint NOT NULL,
    enqueued_at_ms bigint NOT NULL,
    CONSTRAINT concurrency_group_pending_runs_time_nonnegative CHECK ((enqueued_at_ms >= 0))
);

ALTER TABLE concurrency_group_pending_runs ALTER COLUMN queue_sequence ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME concurrency_group_pending_runs_queue_sequence_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE concurrency_groups (
    repository_id uuid NOT NULL,
    normalized_key text NOT NULL,
    display_key text NOT NULL,
    running_run_id uuid,
    generation bigint DEFAULT 1 NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT concurrency_groups_generation_positive CHECK ((generation > 0)),
    CONSTRAINT concurrency_groups_key_nonempty CHECK ((length(normalized_key) > 0))
);

CREATE TABLE delegated_actor_identities (
    issuer text NOT NULL,
    subject uuid NOT NULL,
    principal_id uuid NOT NULL,
    display_name text NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT delegated_actor_identities_display_name_shape CHECK ((((char_length(display_name) >= 1) AND (char_length(display_name) <= 255)) AND (btrim(display_name) = display_name) AND (display_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT delegated_actor_identities_issuer_shape CHECK ((((octet_length(issuer) >= 9) AND (octet_length(issuer) <= 2048)) AND (issuer ~ '^https://'::text) AND (issuer !~ '[[:cntrl:][:space:]]'::text))),
    CONSTRAINT delegated_actor_identities_subject_non_nil CHECK ((subject <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT delegated_actor_identities_time_monotonic CHECK (((created_at_ms >= 0) AND (updated_at_ms >= created_at_ms)))
);

CREATE TABLE github_actions_cache_block_commits (
    entry_id uuid NOT NULL,
    list_digest bytea NOT NULL,
    block_ids text[] NOT NULL,
    size_bytes bigint NOT NULL,
    committed_at_seconds bigint CONSTRAINT github_actions_cache_block_commit_committed_at_seconds_not_null NOT NULL,
    CONSTRAINT gha_cache_commits_count CHECK ((((cardinality(block_ids) >= 0) AND (cardinality(block_ids) <= 50000)) AND (array_position(block_ids, NULL::text) IS NULL))),
    CONSTRAINT gha_cache_commits_digest CHECK ((octet_length(list_digest) = 32)),
    CONSTRAINT gha_cache_commits_size CHECK (((size_bytes >= 0) AND (size_bytes <= '10737418240'::bigint)))
);

CREATE TABLE github_actions_cache_blocks (
    entry_id uuid NOT NULL,
    block_id text NOT NULL,
    object_key text NOT NULL,
    digest bytea NOT NULL,
    size_bytes bigint NOT NULL,
    media_type text NOT NULL,
    state text DEFAULT 'reserved'::text NOT NULL,
    staged_at_seconds bigint NOT NULL,
    ready_at_seconds bigint,
    CONSTRAINT gha_cache_blocks_digest CHECK ((octet_length(digest) = 32)),
    CONSTRAINT gha_cache_blocks_id_shape CHECK ((((octet_length(block_id) >= 4) AND (octet_length(block_id) <= 128)) AND (block_id !~ '[[:space:][:cntrl:]]'::text))),
    CONSTRAINT gha_cache_blocks_key_shape CHECK ((((octet_length(object_key) >= 1) AND (octet_length(object_key) <= 1024)) AND (object_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT gha_cache_blocks_media_type CHECK ((((octet_length(media_type) >= 3) AND (octet_length(media_type) <= 128)) AND (media_type !~ '[[:space:][:cntrl:];]'::text))),
    CONSTRAINT gha_cache_blocks_readiness CHECK ((((state = 'reserved'::text) AND (ready_at_seconds IS NULL)) OR ((state = 'ready'::text) AND (ready_at_seconds >= staged_at_seconds)))),
    CONSTRAINT gha_cache_blocks_size CHECK (((size_bytes >= 0) AND (size_bytes <= 134217728))),
    CONSTRAINT gha_cache_blocks_state CHECK ((state = ANY (ARRAY['reserved'::text, 'ready'::text])))
);

CREATE TABLE github_actions_cache_entries (
    id uuid NOT NULL,
    protocol_entry_id bigint NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    run_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    cache_ref text NOT NULL,
    cache_key text NOT NULL,
    cache_version text NOT NULL,
    block_id_encoded_length integer,
    state text DEFAULT 'pending'::text NOT NULL,
    content_digest bytea,
    content_size_bytes bigint,
    created_at_seconds bigint NOT NULL,
    finalized_at_seconds bigint,
    last_accessed_at_seconds bigint NOT NULL,
    CONSTRAINT gha_cache_block_id_length CHECK (((block_id_encoded_length IS NULL) OR ((block_id_encoded_length >= 4) AND (block_id_encoded_length <= 128)))),
    CONSTRAINT gha_cache_fence_positive CHECK ((fencing_token > 0)),
    CONSTRAINT gha_cache_key_shape CHECK ((((octet_length(cache_key) >= 1) AND (octet_length(cache_key) <= 512)) AND (cache_key !~ '[,[:cntrl:]]'::text))),
    CONSTRAINT gha_cache_publication_shape CHECK ((((state = 'pending'::text) AND (content_digest IS NULL) AND (content_size_bytes IS NULL) AND (finalized_at_seconds IS NULL)) OR ((state = 'finalized'::text) AND (octet_length(content_digest) = 32) AND (content_size_bytes >= 0) AND (finalized_at_seconds IS NOT NULL) AND (last_accessed_at_seconds >= finalized_at_seconds)))),
    CONSTRAINT gha_cache_ref_shape CHECK ((((octet_length(cache_ref) >= 6) AND (octet_length(cache_ref) <= 1024)) AND (cache_ref ~~ 'refs/%'::text) AND (cache_ref !~ '[[:space:][:cntrl:]]'::text))),
    CONSTRAINT gha_cache_state CHECK ((state = ANY (ARRAY['pending'::text, 'finalized'::text]))),
    CONSTRAINT gha_cache_times CHECK (((created_at_seconds >= 0) AND (last_accessed_at_seconds >= created_at_seconds) AND ((finalized_at_seconds IS NULL) OR (finalized_at_seconds >= created_at_seconds)))),
    CONSTRAINT gha_cache_version_shape CHECK ((((octet_length(cache_version) >= 1) AND (octet_length(cache_version) <= 512)) AND (cache_version !~ '[[:space:][:cntrl:]]'::text)))
);

ALTER TABLE github_actions_cache_entries ALTER COLUMN protocol_entry_id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME github_actions_cache_entries_protocol_entry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE github_check_projection_outbox (
    subject_id uuid NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempted_revision bigint,
    attempt_count smallint DEFAULT 0 NOT NULL,
    claim_fence bigint DEFAULT 0 NOT NULL,
    claim_owner_id uuid,
    claim_action text,
    claimed_desired_revision bigint,
    claimed_desired_state text,
    claimed_desired_conclusion text,
    claimed_at_ms bigint,
    claim_expires_at_ms bigint,
    next_attempt_at_ms bigint,
    last_failure_kind text COLLATE pg_catalog."C",
    external_suite_id bigint,
    external_run_id bigint,
    external_bound_at_ms bigint,
    create_owner_id uuid,
    create_fence bigint,
    create_started_at_ms bigint,
    create_issue_expires_at_ms bigint,
    reconcile_not_before_ms bigint,
    next_reconcile_at_ms bigint,
    projected_revision bigint DEFAULT 0 NOT NULL,
    provider_state text,
    provider_conclusion text,
    provider_observed_at_ms bigint,
    blocked_reason text,
    state_updated_at_ms bigint NOT NULL,
    CONSTRAINT github_check_projection_outbox_action_shape CHECK (((state <> 'claimed'::text) OR
CASE claim_action
    WHEN 'ensure_suite'::text THEN ((external_suite_id IS NULL) AND (external_run_id IS NULL))
    WHEN 'prepare_run_create'::text THEN ((external_suite_id IS NOT NULL) AND (external_run_id IS NULL) AND (create_started_at_ms IS NULL))
    WHEN 'reconcile_run_create'::text THEN ((external_suite_id IS NOT NULL) AND (external_run_id IS NULL) AND (create_started_at_ms IS NOT NULL))
    WHEN 'publish'::text THEN ((external_suite_id IS NOT NULL) AND (external_run_id IS NOT NULL))
    ELSE false
END)),
    CONSTRAINT github_check_projection_outbox_attempt CHECK ((((attempt_count >= 0) AND (attempt_count <= 64)) AND (claim_fence >= 0) AND ((attempted_revision IS NULL) OR (attempted_revision > 0)))),
    CONSTRAINT github_check_projection_outbox_block_shape CHECK ((((state = 'blocked'::text) AND (blocked_reason = ANY (ARRAY['ambiguous_create'::text, 'annotation_mismatch'::text, 'attempt_limit'::text, 'credential_rejected'::text]))) OR ((state <> 'blocked'::text) AND (blocked_reason IS NULL)))),
    CONSTRAINT github_check_projection_outbox_claim_shape CHECK ((((state <> 'claimed'::text) AND (claim_owner_id IS NULL) AND (claim_action IS NULL) AND (claimed_desired_revision IS NULL) AND (claimed_desired_state IS NULL) AND (claimed_desired_conclusion IS NULL) AND (claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL)) OR ((state = 'claimed'::text) AND (claim_owner_id IS NOT NULL) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_action = ANY (ARRAY['ensure_suite'::text, 'prepare_run_create'::text, 'reconcile_run_create'::text, 'publish'::text])) AND (claimed_desired_revision > 0) AND (claimed_desired_state = ANY (ARRAY['queued'::text, 'in_progress'::text, 'completed'::text])) AND (((claimed_desired_state = 'completed'::text) AND (claimed_desired_conclusion = ANY (ARRAY['action_required'::text, 'cancelled'::text, 'failure'::text, 'success'::text, 'skipped'::text, 'timed_out'::text]))) OR ((claimed_desired_state <> 'completed'::text) AND (claimed_desired_conclusion IS NULL))) AND (claimed_at_ms >= 0) AND (claim_expires_at_ms > claimed_at_ms) AND ((claim_expires_at_ms - claimed_at_ms) <= 900000)))),
    CONSTRAINT github_check_projection_outbox_create_shape CHECK ((((create_started_at_ms IS NULL) AND (create_owner_id IS NULL) AND (create_fence IS NULL) AND (create_issue_expires_at_ms IS NULL) AND (reconcile_not_before_ms IS NULL) AND (next_reconcile_at_ms IS NULL)) OR ((create_started_at_ms >= 0) AND (create_owner_id IS NOT NULL) AND (create_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (create_fence > 0) AND (create_issue_expires_at_ms > create_started_at_ms) AND ((create_issue_expires_at_ms - create_started_at_ms) <= 900000) AND (reconcile_not_before_ms > create_issue_expires_at_ms) AND ((reconcile_not_before_ms - create_issue_expires_at_ms) <= 420000) AND (next_reconcile_at_ms >= reconcile_not_before_ms) AND (external_suite_id IS NOT NULL) AND (external_run_id IS NULL)))),
    CONSTRAINT github_check_projection_outbox_delivery_shape CHECK (((state <> 'delivered'::text) OR ((projected_revision > 0) AND (provider_state IS NOT NULL) AND (external_run_id IS NOT NULL)))),
    CONSTRAINT github_check_projection_outbox_external CHECK ((((external_suite_id IS NULL) OR (external_suite_id > 0)) AND ((external_run_id IS NULL) OR (external_run_id > 0)) AND ((external_run_id IS NULL) OR (external_suite_id IS NOT NULL)) AND (((external_run_id IS NULL) AND (external_bound_at_ms IS NULL)) OR ((external_run_id IS NOT NULL) AND (external_bound_at_ms >= 0))))),
    CONSTRAINT github_check_projection_outbox_failure_shape CHECK (((last_failure_kind IS NULL) OR (((octet_length(last_failure_kind) >= 1) AND (octet_length(last_failure_kind) <= 128)) AND (last_failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)))),
    CONSTRAINT github_check_projection_outbox_indeterminate_shape CHECK (((state <> 'create_indeterminate'::text) OR (create_started_at_ms IS NOT NULL))),
    CONSTRAINT github_check_projection_outbox_provider_shape CHECK (((projected_revision >= 0) AND (((provider_state IS NULL) AND (provider_conclusion IS NULL) AND (provider_observed_at_ms IS NULL)) OR ((provider_state = ANY (ARRAY['queued'::text, 'in_progress'::text])) AND (provider_conclusion IS NULL) AND (provider_observed_at_ms >= 0) AND (external_run_id IS NOT NULL)) OR ((provider_state = 'completed'::text) AND (provider_conclusion = ANY (ARRAY['action_required'::text, 'cancelled'::text, 'failure'::text, 'success'::text, 'skipped'::text, 'timed_out'::text])) AND (provider_observed_at_ms >= 0) AND (external_run_id IS NOT NULL))))),
    CONSTRAINT github_check_projection_outbox_retry_shape CHECK ((((state = 'retry'::text) AND (next_attempt_at_ms > state_updated_at_ms) AND ((next_attempt_at_ms - state_updated_at_ms) <= 86400000) AND (last_failure_kind IS NOT NULL)) OR ((state <> 'retry'::text) AND (next_attempt_at_ms IS NULL) AND (last_failure_kind IS NULL)))),
    CONSTRAINT github_check_projection_outbox_state CHECK ((state = ANY (ARRAY['pending'::text, 'claimed'::text, 'retry'::text, 'create_indeterminate'::text, 'delivered'::text, 'blocked'::text]))),
    CONSTRAINT github_check_projection_outbox_time CHECK ((state_updated_at_ms >= 0))
);

CREATE TABLE github_check_subjects (
    id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_delivery_id uuid,
    subject_key text NOT NULL COLLATE pg_catalog."C",
    provider_connection_id uuid NOT NULL,
    provider_installation_id bigint NOT NULL,
    github_repository_id bigint NOT NULL,
    github_app_id bigint NOT NULL,
    head_sha bytea NOT NULL,
    check_name text NOT NULL COLLATE pg_catalog."C",
    external_id text NOT NULL COLLATE pg_catalog."C",
    workflow_run_id uuid,
    linked_at_ms bigint,
    desired_state text DEFAULT 'queued'::text NOT NULL,
    desired_conclusion text,
    terminal_cause text,
    desired_revision bigint DEFAULT 1 NOT NULL,
    created_at_ms bigint NOT NULL,
    desired_updated_at_ms bigint NOT NULL,
    github_repository_name text NOT NULL COLLATE pg_catalog."C",
    origin_kind text DEFAULT 'provider_delivery'::text NOT NULL COLLATE pg_catalog."C",
    workflow_rerun_run_id uuid,
    subject_kind text DEFAULT 'workflow'::text NOT NULL COLLATE pg_catalog."C",
    parent_subject_id uuid,
    job_id uuid,
    job_attempt_id uuid,
    CONSTRAINT github_check_subjects_desired_shape CHECK (((desired_revision > 0) AND (created_at_ms >= 0) AND (desired_updated_at_ms >= created_at_ms) AND (((desired_state = ANY (ARRAY['queued'::text, 'in_progress'::text])) AND (desired_conclusion IS NULL) AND (terminal_cause IS NULL)) OR ((desired_state = 'completed'::text) AND (desired_conclusion = ANY (ARRAY['action_required'::text, 'cancelled'::text, 'failure'::text, 'success'::text, 'skipped'::text, 'timed_out'::text])) AND (terminal_cause = ANY (ARRAY['workflow_success'::text, 'workflow_skipped'::text, 'workflow_failure'::text, 'workflow_cancelled'::text, 'workflow_timed_out'::text, 'provider_unknown'::text, 'system_unknown'::text])))))),
    CONSTRAINT github_check_subjects_external_id_exact CHECK (((external_id = ('automata-check:'::text || (id)::text)) AND (octet_length(external_id) <= 1024))),
    CONSTRAINT github_check_subjects_key_shape CHECK ((((octet_length(subject_key) >= 1) AND (octet_length(subject_key) <= 1024)) AND (btrim(subject_key) = subject_key) AND (subject_key !~ '[[:cntrl:]\\]'::text) AND ("left"(subject_key, 1) <> '/'::text) AND (subject_key !~ '(^|/)(\.|\.\.)(/|$)'::text) AND (subject_key !~ '//'::text))),
    CONSTRAINT github_check_subjects_link_shape CHECK ((((workflow_run_id IS NULL) AND (linked_at_ms IS NULL)) OR ((workflow_run_id IS NOT NULL) AND (linked_at_ms >= created_at_ms)))),
    CONSTRAINT github_check_subjects_name_shape CHECK ((((octet_length(check_name) >= 1) AND (octet_length(check_name) <= 255)) AND (check_name = btrim(check_name)) AND (check_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT github_check_subjects_non_nil CHECK (((id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_delivery_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((workflow_run_id IS NULL) OR (workflow_run_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((parent_subject_id IS NULL) OR (parent_subject_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((job_id IS NULL) OR (job_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((job_attempt_id IS NULL) OR (job_attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT github_check_subjects_numeric_identity CHECK (((provider_installation_id > 0) AND (github_repository_id > 0) AND (github_app_id > 0))),
    CONSTRAINT github_check_subjects_origin_exact CHECK (((num_nonnulls(provider_delivery_id, workflow_rerun_run_id) = 1) AND (((origin_kind = 'provider_delivery'::text) AND (provider_delivery_id IS NOT NULL) AND (workflow_rerun_run_id IS NULL)) OR ((origin_kind = 'workflow_rerun'::text) AND (provider_delivery_id IS NULL) AND (workflow_rerun_run_id IS NOT NULL))))),
    CONSTRAINT github_check_subjects_repository_name_shape CHECK ((((octet_length(github_repository_name) >= 3) AND (octet_length(github_repository_name) <= 140)) AND (github_repository_name ~ '^[^/]+/[^/]+$'::text) AND ((octet_length(split_part(github_repository_name, '/'::text, 1)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 1)) <= 39)) AND ((octet_length(split_part(github_repository_name, '/'::text, 2)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 2)) <= 100)) AND ((split_part(github_repository_name, '/'::text, 1) ~ '^[A-Za-z0-9]$'::text) OR (split_part(github_repository_name, '/'::text, 1) ~ '^[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]$'::text)) AND (split_part(github_repository_name, '/'::text, 1) !~ '--'::text) AND (split_part(github_repository_name, '/'::text, 2) ~ '^[A-Za-z0-9._-]+$'::text) AND (split_part(github_repository_name, '/'::text, 2) <> ALL (ARRAY['.'::text, '..'::text])) AND (split_part(github_repository_name, '/'::text, 2) !~* '[.]git$'::text))),
    CONSTRAINT github_check_subjects_sha CHECK (((octet_length(head_sha) = 20) AND (head_sha <> decode(repeat('00'::text, 20), 'hex'::text)))),
    CONSTRAINT github_check_subjects_terminal_mapping CHECK (((desired_state <> 'completed'::text) OR
CASE terminal_cause
    WHEN 'workflow_success'::text THEN (desired_conclusion = 'success'::text)
    WHEN 'workflow_skipped'::text THEN (desired_conclusion = 'skipped'::text)
    WHEN 'workflow_failure'::text THEN (desired_conclusion = 'failure'::text)
    WHEN 'workflow_cancelled'::text THEN (desired_conclusion = 'cancelled'::text)
    WHEN 'workflow_timed_out'::text THEN (desired_conclusion = 'timed_out'::text)
    WHEN 'provider_unknown'::text THEN (desired_conclusion = 'action_required'::text)
    WHEN 'system_unknown'::text THEN (desired_conclusion = 'failure'::text)
    ELSE false
END)),
    CONSTRAINT github_check_subjects_subject_shape CHECK ((((subject_kind = 'workflow'::text) AND (parent_subject_id IS NULL) AND (job_id IS NULL) AND (job_attempt_id IS NULL)) OR ((subject_kind = 'job'::text) AND (parent_subject_id IS NOT NULL) AND (job_id IS NOT NULL) AND (job_attempt_id IS NOT NULL)))),
    CONSTRAINT github_check_subjects_workflow_rerun_non_nil CHECK (((workflow_rerun_run_id IS NULL) OR (workflow_rerun_run_id <> '00000000-0000-0000-0000-000000000000'::uuid)))
);

CREATE TABLE github_check_annotation_progress (
    subject_id uuid PRIMARY KEY,
    presentation_digest bytea NOT NULL,
    annotation_total integer NOT NULL,
    annotation_next integer DEFAULT 0 NOT NULL,
    uncertain_batch_size smallint,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT github_check_annotation_progress_digest CHECK ((octet_length(presentation_digest) = 32)),
    CONSTRAINT github_check_annotation_progress_cursor CHECK (((annotation_total >= 0) AND (annotation_total <= 4096) AND (annotation_next >= 0) AND (annotation_next <= annotation_total))),
    CONSTRAINT github_check_annotation_progress_uncertainty CHECK (((uncertain_batch_size IS NULL) OR ((uncertain_batch_size >= 1) AND (uncertain_batch_size <= 50) AND ((annotation_next + uncertain_batch_size) <= annotation_total)))),
    CONSTRAINT github_check_annotation_progress_time CHECK ((updated_at_ms >= 0))
);

CREATE TABLE github_membership_snapshots (
    tenant_id text NOT NULL,
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    provider_id text DEFAULT 'github'::text NOT NULL,
    provider_subject text NOT NULL,
    provider_token_version bigint NOT NULL,
    observed_at_ms bigint NOT NULL,
    valid_until_ms bigint NOT NULL,
    CONSTRAINT github_membership_snapshots_provider CHECK ((provider_id = 'github'::text)),
    CONSTRAINT github_membership_snapshots_token_version_positive CHECK ((provider_token_version > 0)),
    CONSTRAINT github_membership_snapshots_validity CHECK ((valid_until_ms > observed_at_ms))
);

CREATE TABLE github_oidc_issuance_slots (
    authority_id uuid NOT NULL,
    audience_key_sha256 bytea NOT NULL,
    requested_audience text COLLATE pg_catalog."C",
    generation bigint NOT NULL,
    token_id uuid NOT NULL,
    signing_key_id text NOT NULL COLLATE pg_catalog."C",
    resolved_audience text NOT NULL COLLATE pg_catalog."C",
    issued_at_seconds bigint NOT NULL,
    not_before_seconds bigint NOT NULL,
    expires_at_seconds bigint NOT NULL,
    created_at_seconds bigint NOT NULL,
    updated_at_seconds bigint NOT NULL,
    CONSTRAINT github_oidc_issuance_slots_audience CHECK ((((octet_length(resolved_audience) >= 1) AND (octet_length(resolved_audience) <= 2048)) AND (btrim(resolved_audience) <> ''::text) AND (resolved_audience !~ '[[:cntrl:]]'::text))),
    CONSTRAINT github_oidc_issuance_slots_digest CHECK ((octet_length(audience_key_sha256) = 32)),
    CONSTRAINT github_oidc_issuance_slots_generation CHECK ((generation > 0)),
    CONSTRAINT github_oidc_issuance_slots_identity CHECK (((token_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((octet_length(signing_key_id) >= 1) AND (octet_length(signing_key_id) <= 128)) AND (signing_key_id ~ '^[A-Za-z0-9._-]+$'::text))),
    CONSTRAINT github_oidc_issuance_slots_interval CHECK (((issued_at_seconds >= 0) AND (not_before_seconds >= 0) AND (not_before_seconds <= issued_at_seconds) AND (expires_at_seconds > issued_at_seconds) AND ((expires_at_seconds - issued_at_seconds) <= 3600) AND (issued_at_seconds <= '9223372036854775'::bigint) AND (created_at_seconds >= 0) AND (updated_at_seconds >= created_at_seconds) AND (updated_at_seconds = issued_at_seconds))),
    CONSTRAINT github_oidc_issuance_slots_requested_audience CHECK (((requested_audience IS NULL) OR (((octet_length(requested_audience) >= 1) AND (octet_length(requested_audience) <= 2048)) AND (btrim(requested_audience) <> ''::text) AND (requested_audience !~ '[[:cntrl:]]'::text))))
);

CREATE TABLE github_oidc_key_deadlines (
    key_use text NOT NULL COLLATE pg_catalog."C",
    key_id text NOT NULL COLLATE pg_catalog."C",
    key_sha256 bytea,
    max_not_after_seconds bigint NOT NULL,
    updated_at_seconds bigint NOT NULL,
    CONSTRAINT github_oidc_key_deadlines_key CHECK ((((octet_length(key_id) >= 1) AND (octet_length(key_id) <= 128)) AND (key_id ~ '^[A-Za-z0-9._-]+$'::text) AND ((key_sha256 IS NULL) OR (octet_length(key_sha256) = 32)))),
    CONSTRAINT github_oidc_key_deadlines_time CHECK (((max_not_after_seconds > 0) AND (updated_at_seconds >= 0) AND (updated_at_seconds <= max_not_after_seconds))),
    CONSTRAINT github_oidc_key_deadlines_use CHECK ((key_use = ANY (ARRAY['request_bearer'::text, 'id_token_signing'::text])))
);

CREATE TABLE github_organization_membership_observations (
    tenant_id text NOT NULL,
    snapshot_id uuid CONSTRAINT github_organization_membership_observation_snapshot_id_not_null NOT NULL,
    organization_id bigint CONSTRAINT github_organization_membership_observa_organization_id_not_null NOT NULL,
    organization_login text CONSTRAINT github_organization_membership_obse_organization_login_not_null NOT NULL,
    membership_role text CONSTRAINT github_organization_membership_observa_membership_role_not_null NOT NULL,
    CONSTRAINT github_organization_membership_observations_id_positive CHECK ((organization_id > 0)),
    CONSTRAINT github_organization_membership_observations_login_shape CHECK ((((octet_length(organization_login) >= 1) AND (octet_length(organization_login) <= 255)) AND (organization_login !~ '[[:space:][:cntrl:]]'::text))),
    CONSTRAINT github_organization_membership_observations_role CHECK ((membership_role = ANY (ARRAY['member'::text, 'admin'::text])))
);

CREATE TABLE github_provider_delivery_evidence (
    provider_delivery_id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid CONSTRAINT github_provider_delivery_eviden_provider_connection_id_not_null NOT NULL,
    provider_installation_id bigint CONSTRAINT github_provider_delivery_evid_provider_installation_id_not_null NOT NULL,
    github_repository_id bigint NOT NULL,
    github_repository_owner_id bigint CONSTRAINT github_provider_delivery_ev_github_repository_owner_id_not_null NOT NULL,
    github_repository_name text CONSTRAINT github_provider_delivery_eviden_github_repository_name_not_null NOT NULL COLLATE pg_catalog."C",
    repository_visibility text CONSTRAINT github_provider_delivery_evidenc_repository_visibility_not_null NOT NULL COLLATE pg_catalog."C",
    provider_manifest_revision bigint CONSTRAINT github_provider_delivery_ev_provider_manifest_revision_not_null NOT NULL,
    provider_manifest_digest bytea CONSTRAINT github_provider_delivery_evid_provider_manifest_digest_not_null NOT NULL,
    authenticated_webhook_verifier_fingerprint_sha256 bytea CONSTRAINT github_provider_delivery_ev_authenticated_webhook_veri_not_null NOT NULL,
    authenticated_webhook_verifier_revision bigint CONSTRAINT github_provider_delivery_e_authenticated_webhook_veri_not_null1 NOT NULL,
    checks_authority_id uuid NOT NULL,
    checks_authority_identity_digest bytea CONSTRAINT github_provider_delivery_ev_checks_authority_identity__not_null NOT NULL,
    checks_authority_app_configuration_revision bigint CONSTRAINT github_provider_delivery_ev_checks_authority_app_confi_not_null NOT NULL,
    checks_authority_policy_revision bigint CONSTRAINT github_provider_delivery_ev_checks_authority_policy_re_not_null NOT NULL,
    repository_contents_authority_id uuid NOT NULL,
    repository_contents_authority_identity_digest bytea NOT NULL,
    repository_contents_authority_app_configuration_revision bigint NOT NULL,
    repository_contents_authority_policy_revision bigint NOT NULL,
    github_check_subject_id uuid CONSTRAINT github_provider_delivery_evide_github_check_subject_id_not_null NOT NULL,
    github_check_head_sha bytea CONSTRAINT github_provider_delivery_evidenc_github_check_head_sha_not_null NOT NULL,
    authenticated_event_envelope_version smallint NOT NULL,
    authenticated_event_name text NOT NULL COLLATE pg_catalog."C",
    authenticated_event_git_ref text NOT NULL COLLATE pg_catalog."C",
    authenticated_event_source_revision bytea,
    authenticated_event_source_authority text COLLATE pg_catalog."C",
    CONSTRAINT github_provider_delivery_evidence_authenticated_event CHECK ((((authenticated_event_envelope_version = 1) AND (authenticated_event_name = ANY (ARRAY['push'::text, 'pull_request'::text, 'merge_group'::text])) AND ((octet_length(authenticated_event_git_ref) >= 6) AND (octet_length(authenticated_event_git_ref) <= 1024)) AND (authenticated_event_git_ref ~~ 'refs/%'::text) AND (authenticated_event_git_ref !~ '[[:cntrl:]]'::text) AND (authenticated_event_source_revision IS NULL) AND (authenticated_event_source_authority IS NULL)) OR ((authenticated_event_envelope_version = 1) AND (authenticated_event_name = 'repository_dispatch'::text) AND ((octet_length(authenticated_event_git_ref) >= 12) AND (octet_length(authenticated_event_git_ref) <= 1024)) AND (authenticated_event_git_ref ~~ 'refs/heads/%'::text) AND (authenticated_event_git_ref !~ '[[:cntrl:]]'::text) AND (octet_length(authenticated_event_source_revision) = 20) AND (authenticated_event_source_revision <> decode(repeat('00'::text, 20), 'hex'::text)) AND (authenticated_event_source_authority = 'repository_contents_read'::text)))),
    CONSTRAINT github_provider_delivery_evidence_digest_shape CHECK (((octet_length(provider_manifest_digest) = 32) AND (octet_length(authenticated_webhook_verifier_fingerprint_sha256) = 32) AND (authenticated_webhook_verifier_fingerprint_sha256 <> decode(repeat('00'::text, 32), 'hex'::text)) AND (octet_length(checks_authority_identity_digest) = 32) AND (octet_length(repository_contents_authority_identity_digest) = 32) AND (octet_length(github_check_head_sha) = 20) AND (github_check_head_sha <> decode(repeat('00'::text, 20), 'hex'::text)))),
    CONSTRAINT github_provider_delivery_evidence_non_nil CHECK (((provider_delivery_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (checks_authority_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (github_check_subject_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_contents_authority_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT github_provider_delivery_evidence_positive CHECK (((provider_installation_id > 0) AND (github_repository_id > 0) AND (github_repository_owner_id > 0) AND (provider_manifest_revision > 0) AND (authenticated_webhook_verifier_revision > 0) AND (checks_authority_app_configuration_revision > 0) AND (checks_authority_policy_revision > 0) AND (repository_contents_authority_app_configuration_revision > 0) AND (repository_contents_authority_policy_revision > 0))),
    CONSTRAINT github_provider_delivery_evidence_repository_contents_selector_shape CHECK ((repository_contents_authority_id <> checks_authority_id) AND (repository_contents_authority_identity_digest <> checks_authority_identity_digest)),
    CONSTRAINT github_provider_delivery_evidence_repository_name CHECK (((array_length(string_to_array(github_repository_name, '/'::text), 1) = 2) AND ((octet_length(split_part(github_repository_name, '/'::text, 1)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 1)) <= 39)) AND (split_part(github_repository_name, '/'::text, 1) ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$'::text) AND (split_part(github_repository_name, '/'::text, 1) !~ '--'::text) AND ((octet_length(split_part(github_repository_name, '/'::text, 2)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 2)) <= 100)) AND (split_part(github_repository_name, '/'::text, 2) ~ '^[A-Za-z0-9._-]+$'::text) AND (split_part(github_repository_name, '/'::text, 2) <> ALL (ARRAY['.'::text, '..'::text])) AND (split_part(github_repository_name, '/'::text, 2) !~* '[.]git$'::text))),
    CONSTRAINT github_provider_delivery_evidence_visibility CHECK ((repository_visibility = ANY (ARRAY['public'::text, 'private'::text])))
);

CREATE TABLE github_provider_manifest_current (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid CONSTRAINT github_provider_manifest_curren_provider_connection_id_not_null NOT NULL,
    manifest_revision bigint NOT NULL,
    manifest_digest bytea NOT NULL,
    activated_at_ms bigint NOT NULL,
    CONSTRAINT github_provider_manifest_current_non_nil CHECK (((repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT github_provider_manifest_current_shape CHECK (((manifest_revision > 0) AND (octet_length(manifest_digest) = 32) AND (activated_at_ms >= 0)))
);

CREATE TABLE github_repository_dispatch_pending_evidence (
    provider_delivery_id uuid CONSTRAINT github_repository_dispatch_pendin_provider_delivery_id_not_null NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid CONSTRAINT github_repository_dispatch_pending_evide_repository_id_not_null NOT NULL,
    provider_connection_id uuid CONSTRAINT github_repository_dispatch_pend_provider_connection_id_not_null NOT NULL,
    github_repository_owner_id bigint CONSTRAINT github_repository_dispatch__github_repository_owner_id_not_null NOT NULL,
    provider_manifest_revision bigint CONSTRAINT github_repository_dispatch__provider_manifest_revision_not_null NOT NULL,
    provider_manifest_digest bytea CONSTRAINT github_repository_dispatch_pe_provider_manifest_digest_not_null NOT NULL,
    authenticated_webhook_verifier_fingerprint_sha256 bytea CONSTRAINT github_repository_dispatch__authenticated_webhook_veri_not_null NOT NULL,
    authenticated_webhook_verifier_revision bigint CONSTRAINT github_repository_dispatch_authenticated_webhook_veri_not_null1 NOT NULL,
    authenticated_event_envelope_version smallint CONSTRAINT github_repository_dispatch__authenticated_event_envelo_not_null NOT NULL,
    authenticated_event_name text CONSTRAINT github_repository_dispatch_pe_authenticated_event_name_not_null NOT NULL COLLATE pg_catalog."C",
    authenticated_event_git_ref text CONSTRAINT github_repository_dispatch__authenticated_event_git_re_not_null NOT NULL COLLATE pg_catalog."C",
    checks_authority_id uuid CONSTRAINT github_repository_dispatch_pending_checks_authority_id_not_null NOT NULL,
    checks_authority_identity_digest bytea CONSTRAINT github_repository_dispatch__checks_authority_identity__not_null NOT NULL,
    checks_authority_app_configuration_revision bigint CONSTRAINT github_repository_dispatch__checks_authority_app_confi_not_null NOT NULL,
    checks_authority_policy_revision bigint CONSTRAINT github_repository_dispatch__checks_authority_policy_re_not_null NOT NULL,
    repository_contents_authority_id uuid NOT NULL,
    repository_contents_authority_identity_digest bytea NOT NULL,
    repository_contents_authority_app_configuration_revision bigint NOT NULL,
    repository_contents_authority_policy_revision bigint NOT NULL,
    CONSTRAINT github_repository_dispatch_pending_shape CHECK (((provider_delivery_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (github_repository_owner_id > 0) AND (provider_manifest_revision > 0) AND (authenticated_webhook_verifier_revision > 0) AND (octet_length(provider_manifest_digest) = 32) AND (octet_length(authenticated_webhook_verifier_fingerprint_sha256) = 32) AND (authenticated_event_envelope_version = 1) AND (authenticated_event_name = 'repository_dispatch'::text) AND ((octet_length(authenticated_event_git_ref) >= 12) AND (octet_length(authenticated_event_git_ref) <= 1024)) AND (authenticated_event_git_ref ~~ 'refs/heads/%'::text) AND (authenticated_event_git_ref !~ '[[:cntrl:]]'::text) AND (checks_authority_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (octet_length(checks_authority_identity_digest) = 32) AND (checks_authority_app_configuration_revision > 0) AND (checks_authority_policy_revision > 0) AND (repository_contents_authority_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_contents_authority_id <> checks_authority_id) AND (octet_length(repository_contents_authority_identity_digest) = 32) AND (repository_contents_authority_identity_digest <> checks_authority_identity_digest) AND (repository_contents_authority_app_configuration_revision > 0) AND (repository_contents_authority_policy_revision > 0)))
);

CREATE TABLE github_role_mappings (
    tenant_id text NOT NULL,
    id uuid NOT NULL,
    provider_id text DEFAULT 'github'::text NOT NULL,
    organization_id bigint NOT NULL,
    organization_login text NOT NULL,
    team_id bigint,
    team_slug text,
    role_id uuid NOT NULL,
    scope_kind text NOT NULL,
    repository_id uuid,
    runner_group_id uuid,
    status text DEFAULT 'active'::text NOT NULL,
    created_by_principal_id uuid,
    disabled_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    disabled_at_ms bigint,
    revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT github_role_mappings_membership_shape CHECK (((((team_id IS NULL) AND (team_slug IS NULL)) OR ((team_id > 0) AND ((octet_length(team_slug) >= 1) AND (octet_length(team_slug) <= 255)) AND (team_slug !~ '[[:space:][:cntrl:]]'::text))) IS TRUE)),
    CONSTRAINT github_role_mappings_organization_id_positive CHECK ((organization_id > 0)),
    CONSTRAINT github_role_mappings_organization_login_shape CHECK ((((octet_length(organization_login) >= 1) AND (octet_length(organization_login) <= 255)) AND (organization_login !~ '[[:space:][:cntrl:]]'::text))),
    CONSTRAINT github_role_mappings_provider CHECK ((provider_id = 'github'::text)),
    CONSTRAINT github_role_mappings_revision_positive CHECK ((revision > 0)),
    CONSTRAINT github_role_mappings_scope_kind CHECK ((scope_kind = ANY (ARRAY['tenant'::text, 'repository'::text, 'runner_group'::text]))),
    CONSTRAINT github_role_mappings_scope_shape CHECK (((((scope_kind = 'tenant'::text) AND (repository_id IS NULL) AND (runner_group_id IS NULL)) OR ((scope_kind = 'repository'::text) AND (repository_id IS NOT NULL) AND (runner_group_id IS NULL)) OR ((scope_kind = 'runner_group'::text) AND (repository_id IS NULL) AND (runner_group_id IS NOT NULL))) IS TRUE)),
    CONSTRAINT github_role_mappings_status CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT github_role_mappings_status_shape CHECK (((((status = 'active'::text) AND (disabled_by_principal_id IS NULL) AND (disabled_at_ms IS NULL)) OR ((status = 'disabled'::text) AND (disabled_at_ms >= created_at_ms))) IS TRUE)),
    CONSTRAINT github_role_mappings_time_monotonic CHECK ((updated_at_ms >= created_at_ms))
);

CREATE TABLE github_runtime_authority_lease_renewal_receipts (
    attempt_id uuid CONSTRAINT github_runtime_authority_lease_renewal_rece_attempt_id_not_null NOT NULL,
    fencing_token bigint CONSTRAINT github_runtime_authority_lease_renewal_r_fencing_token_not_null NOT NULL,
    lease_id uuid CONSTRAINT github_runtime_authority_lease_renewal_receip_lease_id_not_null NOT NULL,
    runner_id uuid CONSTRAINT github_runtime_authority_lease_renewal_recei_runner_id_not_null NOT NULL,
    runner_session_id uuid CONSTRAINT github_runtime_authority_lease_renew_runner_session_id_not_null NOT NULL,
    runner_session_epoch bigint CONSTRAINT github_runtime_authority_lease_re_runner_session_epoch_not_null NOT NULL,
    runner_generation bigint CONSTRAINT github_runtime_authority_lease_renew_runner_generation_not_null NOT NULL,
    previous_lease_expires_at_ms bigint CONSTRAINT github_runtime_authority_le_previous_lease_expires_at__not_null NOT NULL,
    renewed_lease_expires_at_ms bigint CONSTRAINT github_runtime_authority_le_renewed_lease_expires_at_m_not_null NOT NULL,
    authorized_at_ms bigint CONSTRAINT github_runtime_authority_lease_renewa_authorized_at_ms_not_null NOT NULL,
    CONSTRAINT github_runtime_authority_lease_renewal_receipts_interval CHECK (((fencing_token > 0) AND (runner_session_epoch > 0) AND (runner_generation > 0) AND (previous_lease_expires_at_ms > authorized_at_ms) AND (renewed_lease_expires_at_ms > previous_lease_expires_at_ms) AND (authorized_at_ms >= 0) AND (renewed_lease_expires_at_ms > authorized_at_ms))),
    CONSTRAINT github_runtime_authority_lease_renewal_receipts_non_nil CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (lease_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (runner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (runner_session_id <> '00000000-0000-0000-0000-000000000000'::uuid)))
);

CREATE TABLE github_runtime_authority_mint_begins (
    tenant_id text NOT NULL,
    attempt_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    claim_fence bigint NOT NULL,
    claim_owner_id uuid NOT NULL,
    claimed_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    started_at_ms bigint NOT NULL,
    provider_request_millis bigint CONSTRAINT github_runtime_authority_mint__provider_request_millis_not_null NOT NULL,
    CONSTRAINT github_runtime_authority_mint_begins_shape CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (fencing_token > 0) AND ((claim_fence >= 1) AND (claim_fence <= 32)) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claimed_at_ms >= 0) AND (expires_at_ms > claimed_at_ms) AND ((started_at_ms >= claimed_at_ms) AND (started_at_ms <= (expires_at_ms - 1))) AND ((provider_request_millis >= 1) AND (provider_request_millis <= 120000)) AND (((started_at_ms)::numeric + (provider_request_millis)::numeric) <= (expires_at_ms)::numeric)))
);

CREATE TABLE github_runtime_authority_mint_claims (
    tenant_id text NOT NULL,
    attempt_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    claim_fence bigint NOT NULL,
    claim_owner_id uuid NOT NULL,
    claimed_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    CONSTRAINT github_runtime_authority_mint_claims_shape CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (fencing_token > 0) AND ((claim_fence >= 1) AND (claim_fence <= 32)) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claimed_at_ms >= 0) AND (expires_at_ms > claimed_at_ms)))
);

CREATE TABLE github_runtime_authority_operation_receipts (
    tenant_id text NOT NULL,
    attempt_id uuid NOT NULL,
    fencing_token bigint CONSTRAINT github_runtime_authority_operation_recei_fencing_token_not_null NOT NULL,
    operation_kind text CONSTRAINT github_runtime_authority_operation_rece_operation_kind_not_null NOT NULL COLLATE pg_catalog."C",
    claim_fence bigint CONSTRAINT github_runtime_authority_operation_receipt_claim_fence_not_null NOT NULL,
    operation_digest bytea CONSTRAINT github_runtime_authority_operation_re_operation_digest_not_null NOT NULL,
    disposition text CONSTRAINT github_runtime_authority_operation_receipt_disposition_not_null NOT NULL COLLATE pg_catalog."C",
    claim_owner_id uuid,
    claim_claimed_at_ms bigint,
    claim_expires_at_ms bigint,
    result_state text CONSTRAINT github_runtime_authority_operation_receip_result_state_not_null NOT NULL COLLATE pg_catalog."C",
    result_updated_at_ms bigint CONSTRAINT github_runtime_authority_operati_result_updated_at_ms_not_null1 NOT NULL,
    result_terminal_reason text COLLATE pg_catalog."C",
    applied_at_ms bigint CONSTRAINT github_runtime_authority_operation_recei_applied_at_ms_not_null NOT NULL,
    CONSTRAINT github_runtime_authority_operation_receipts_shape CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (fencing_token > 0) AND (octet_length(operation_digest) = 32) AND (disposition = ANY (ARRAY['applied'::text, 'terminal_erasable'::text])) AND (result_updated_at_ms >= 0) AND (applied_at_ms >= 0) AND (operation_kind = ANY (ARRAY['mint_commit'::text, 'quarantine'::text, 'revocation_outcome'::text])) AND (((operation_kind = 'quarantine'::text) AND (claim_fence = 0) AND (claim_owner_id IS NULL) AND (claim_claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL)) OR ((operation_kind <> 'quarantine'::text) AND (claim_fence > 0) AND (claim_owner_id IS NOT NULL) AND (claim_claimed_at_ms >= 0) AND (claim_expires_at_ms > claim_claimed_at_ms)))))
);

CREATE TABLE github_runtime_authority_operation_transitions (
    tenant_id text CONSTRAINT github_runtime_authority_operation_transitio_tenant_id_not_null NOT NULL,
    attempt_id uuid CONSTRAINT github_runtime_authority_operation_transiti_attempt_id_not_null NOT NULL,
    fencing_token bigint CONSTRAINT github_runtime_authority_operation_trans_fencing_token_not_null NOT NULL,
    operation_kind text CONSTRAINT github_runtime_authority_operation_tran_operation_kind_not_null NOT NULL COLLATE pg_catalog."C",
    claim_fence bigint CONSTRAINT github_runtime_authority_operation_transit_claim_fence_not_null NOT NULL,
    claim_owner_id uuid,
    claim_claimed_at_ms bigint,
    claim_expires_at_ms bigint,
    disposition text CONSTRAINT github_runtime_authority_operation_transit_disposition_not_null NOT NULL COLLATE pg_catalog."C",
    request_kind text CONSTRAINT github_runtime_authority_operation_transi_request_kind_not_null NOT NULL COLLATE pg_catalog."C",
    request_observed_at_ms bigint CONSTRAINT github_runtime_authority_operat_request_observed_at_ms_not_null NOT NULL,
    request_retry_at_ms bigint,
    request_failure_kind text COLLATE pg_catalog."C",
    request_commit_disposition text COLLATE pg_catalog."C",
    request_provider_expires_at_ms bigint,
    request_safe_erase_after_ms bigint,
    request_plaintext_schema integer,
    request_plaintext_size_bytes bigint,
    request_plaintext_digest bytea,
    request_aad_digest bytea,
    request_envelope_digest bytea,
    operation_digest bytea CONSTRAINT github_runtime_authority_operation_tr_operation_digest_not_null NOT NULL,
    predecessor_state text CONSTRAINT github_runtime_authority_operation_t_predecessor_state_not_null NOT NULL COLLATE pg_catalog."C",
    predecessor_updated_at_ms bigint CONSTRAINT github_runtime_authority_ope_predecessor_updated_at_ms_not_null NOT NULL,
    result_state text CONSTRAINT github_runtime_authority_operation_transi_result_state_not_null NOT NULL COLLATE pg_catalog."C",
    result_updated_at_ms bigint CONSTRAINT github_runtime_authority_operatio_result_updated_at_ms_not_null NOT NULL,
    result_terminal_reason text COLLATE pg_catalog."C",
    CONSTRAINT github_runtime_authority_operation_transitions_shape CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (fencing_token > 0) AND (octet_length(operation_digest) = 32) AND (disposition = ANY (ARRAY['applied'::text, 'terminal_erasable'::text])) AND (predecessor_updated_at_ms >= 0) AND (result_updated_at_ms >= predecessor_updated_at_ms) AND (((operation_kind = 'mint_commit'::text) AND (request_kind = 'mint_commit'::text) AND ((claim_fence >= 1) AND (claim_fence <= 32)) AND (claim_owner_id IS NOT NULL) AND (claim_claimed_at_ms >= 0) AND (claim_expires_at_ms > claim_claimed_at_ms)) OR ((operation_kind = 'quarantine'::text) AND (request_kind = 'quarantine'::text) AND (claim_fence = 0) AND (claim_owner_id IS NULL) AND (claim_claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL)) OR ((operation_kind = 'revocation_outcome'::text) AND (request_kind = ANY (ARRAY['revocation_retry'::text, 'revocation_defer'::text, 'revocation_confirm'::text])) AND ((claim_fence >= 1) AND (claim_fence <= 64)) AND (claim_owner_id IS NOT NULL) AND (claim_claimed_at_ms >= 0) AND (claim_expires_at_ms > claim_claimed_at_ms))) AND (((disposition = 'applied'::text) AND (((operation_kind = 'mint_commit'::text) AND (predecessor_state = ANY (ARRAY['minting'::text, 'indeterminate'::text])) AND (result_state = ANY (ARRAY['ready'::text, 'revoke_pending'::text, 'revoked'::text]))) OR ((operation_kind = 'quarantine'::text) AND (predecessor_state = ANY (ARRAY['ready'::text, 'revoke_pending'::text])) AND (result_state = ANY (ARRAY['quarantined'::text, 'revoked'::text]))) OR ((operation_kind = 'revocation_outcome'::text) AND (predecessor_state = 'revoke_pending'::text) AND (result_state = ANY (ARRAY['revoke_pending'::text, 'revoked'::text]))))) OR ((disposition = 'terminal_erasable'::text) AND (predecessor_state = result_state) AND (predecessor_updated_at_ms = result_updated_at_ms) AND (((operation_kind = 'mint_commit'::text) AND (result_state = 'revoked'::text) AND (result_terminal_reason = 'indeterminate_authority_expired'::text)) OR ((operation_kind = 'quarantine'::text) AND (result_state = 'revoked'::text) AND (result_terminal_reason IS NOT NULL)) OR ((operation_kind = 'revocation_outcome'::text) AND (result_state = ANY (ARRAY['revoke_pending'::text, 'quarantined'::text, 'revoked'::text]))))))))
);

CREATE TABLE github_runtime_authority_revocation_claims (
    tenant_id text NOT NULL,
    attempt_id uuid NOT NULL,
    fencing_token bigint CONSTRAINT github_runtime_authority_revocation_clai_fencing_token_not_null NOT NULL,
    claim_fence bigint NOT NULL,
    claim_owner_id uuid CONSTRAINT github_runtime_authority_revocation_cla_claim_owner_id_not_null NOT NULL,
    claimed_at_ms bigint CONSTRAINT github_runtime_authority_revocation_clai_claimed_at_ms_not_null NOT NULL,
    expires_at_ms bigint CONSTRAINT github_runtime_authority_revocation_clai_expires_at_ms_not_null NOT NULL,
    aad_digest bytea NOT NULL,
    safe_erase_after_ms bigint CONSTRAINT github_runtime_authority_revocatio_safe_erase_after_ms_not_null NOT NULL,
    CONSTRAINT github_runtime_authority_revocation_claims_shape CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (fencing_token > 0) AND ((claim_fence >= 1) AND (claim_fence <= 64)) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claimed_at_ms >= 0) AND (expires_at_ms > claimed_at_ms) AND (safe_erase_after_ms > expires_at_ms) AND (octet_length(aad_digest) = 32)))
);

CREATE TABLE github_schedule_discovery_claims (
    discovery_id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid CONSTRAINT github_schedule_discovery_claim_provider_connection_id_not_null NOT NULL,
    manifest_revision bigint NOT NULL,
    manifest_digest bytea NOT NULL,
    github_repository_owner_id bigint CONSTRAINT github_schedule_discovery_c_github_repository_owner_id_not_null NOT NULL,
    source_authority_kind text NOT NULL COLLATE pg_catalog."C",
    repository_contents_authority_id uuid NOT NULL,
    repository_contents_authority_identity_digest bytea NOT NULL,
    repository_contents_authority_app_configuration_revision bigint NOT NULL,
    repository_contents_authority_policy_revision bigint NOT NULL,
    claim_owner_id uuid NOT NULL,
    claim_fence bigint NOT NULL,
    state text NOT NULL COLLATE pg_catalog."C",
    claimed_at_ms bigint NOT NULL,
    claim_expires_at_ms bigint NOT NULL,
    completed_registry_id uuid,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT github_schedule_discovery_claims_non_nil CHECK (((discovery_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT github_schedule_discovery_claims_shape CHECK (((manifest_revision > 0) AND (octet_length(manifest_digest) = 32) AND (github_repository_owner_id > 0) AND (claim_fence > 0) AND (state = ANY (ARRAY['claimed'::text, 'completed'::text, 'expired'::text])) AND (claimed_at_ms >= 0) AND (claim_expires_at_ms > claimed_at_ms) AND ((claim_expires_at_ms - claimed_at_ms) <= 300000) AND (created_at_ms = claimed_at_ms) AND (updated_at_ms >= created_at_ms) AND (((state = 'claimed'::text) AND (completed_registry_id IS NULL)) OR ((state = 'completed'::text) AND (completed_registry_id IS NOT NULL)) OR ((state = 'expired'::text) AND (completed_registry_id IS NULL))))),
    CONSTRAINT github_schedule_discovery_claims_source_authority_shape CHECK ((source_authority_kind = 'repository_contents_read'::text) AND (octet_length(repository_contents_authority_identity_digest) = 32) AND (repository_contents_authority_app_configuration_revision > 0) AND (repository_contents_authority_policy_revision > 0))
);

CREATE TABLE github_schedule_fire_attempts (
    fire_id uuid NOT NULL,
    attempt smallint NOT NULL,
    claim_fence bigint NOT NULL,
    claim_owner_id uuid NOT NULL,
    claimed_at_ms bigint NOT NULL,
    claim_expires_at_ms bigint NOT NULL,
    concluded_at_ms bigint NOT NULL,
    outcome text NOT NULL COLLATE pg_catalog."C",
    failure_kind text COLLATE pg_catalog."C",
    CONSTRAINT github_schedule_fire_attempts_shape CHECK ((((attempt >= 1) AND (attempt <= 20)) AND (claim_fence > 0) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claimed_at_ms >= 0) AND (claim_expires_at_ms > claimed_at_ms) AND (concluded_at_ms >= claimed_at_ms) AND (((outcome = 'admitted'::text) AND (failure_kind IS NULL)) OR ((outcome = ANY (ARRAY['retry'::text, 'expired'::text, 'skipped'::text, 'failed'::text])) AND ((octet_length(failure_kind) >= 1) AND (octet_length(failure_kind) <= 128)) AND (failure_kind ~ '^[a-z0-9](?:[a-z0-9_.:-]*[a-z0-9])?$|^[a-z0-9]$'::text)))))
);

CREATE TABLE github_schedule_fires (
    fire_id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    registry_id uuid NOT NULL,
    entry_ordinal smallint NOT NULL,
    scheduled_at_ms bigint NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL COLLATE pg_catalog."C",
    attempt_count smallint DEFAULT 0 NOT NULL,
    claim_fence bigint DEFAULT 0 NOT NULL,
    claim_owner_id uuid,
    claimed_at_ms bigint,
    claim_expires_at_ms bigint,
    next_attempt_at_ms bigint NOT NULL,
    workflow_run_id uuid,
    failure_kind text COLLATE pg_catalog."C",
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT github_schedule_fires_bounds CHECK ((((entry_ordinal >= 0) AND (entry_ordinal <= 255)) AND (scheduled_at_ms >= 0) AND ((attempt_count >= 0) AND (attempt_count <= 20)) AND (claim_fence >= 0) AND (next_attempt_at_ms >= scheduled_at_ms) AND (created_at_ms >= 0) AND (updated_at_ms >= created_at_ms))),
    CONSTRAINT github_schedule_fires_non_nil CHECK (((fire_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((claim_owner_id IS NULL) OR (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT github_schedule_fires_state_shape CHECK ((((state = 'pending'::text) AND (claim_owner_id IS NULL) AND (claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL) AND (workflow_run_id IS NULL) AND (failure_kind IS NULL)) OR ((state = 'claimed'::text) AND (attempt_count > 0) AND (claim_fence > 0) AND (claim_owner_id IS NOT NULL) AND (claimed_at_ms IS NOT NULL) AND (claim_expires_at_ms > claimed_at_ms) AND (workflow_run_id IS NULL) AND (failure_kind IS NULL)) OR ((state = 'admitted'::text) AND (claim_owner_id IS NULL) AND (claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL) AND (workflow_run_id IS NOT NULL) AND (failure_kind IS NULL)) OR ((state = ANY (ARRAY['skipped'::text, 'failed'::text])) AND (claim_owner_id IS NULL) AND (claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL) AND (workflow_run_id IS NULL) AND ((octet_length(failure_kind) >= 1) AND (octet_length(failure_kind) <= 128)) AND (failure_kind ~ '^[a-z0-9](?:[a-z0-9_.:-]*[a-z0-9])?$|^[a-z0-9]$'::text))))
);

CREATE TABLE github_schedule_registry_current (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid CONSTRAINT github_schedule_registry_curren_provider_connection_id_not_null NOT NULL,
    registry_id uuid NOT NULL,
    activated_at_ms bigint NOT NULL,
    CONSTRAINT github_schedule_registry_current_time CHECK ((activated_at_ms >= 0))
);

CREATE TABLE github_schedule_registry_entries (
    registry_id uuid NOT NULL,
    ordinal smallint NOT NULL,
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    workflow_source_digest bytea CONSTRAINT github_schedule_registry_entrie_workflow_source_digest_not_null NOT NULL,
    schedule_ordinal smallint NOT NULL,
    cron_expression text NOT NULL COLLATE pg_catalog."C",
    timezone text NOT NULL COLLATE pg_catalog."C",
    entry_digest bytea NOT NULL,
    CONSTRAINT github_schedule_registry_entries_shape CHECK ((((ordinal >= 0) AND (ordinal <= 255)) AND ((schedule_ordinal >= 0) AND (schedule_ordinal <= 63)) AND (workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'::text) AND (workflow_path !~ '[[:cntrl:]\\]'::text) AND (octet_length(workflow_source_digest) = 32) AND (octet_length(entry_digest) = 32) AND ((octet_length(cron_expression) >= 1) AND (octet_length(cron_expression) <= 256)) AND (cron_expression ~ '^[A-Za-z0-9*,/ -]+$'::text) AND (array_length(regexp_split_to_array(btrim(cron_expression), '[[:space:]]+'::text), 1) = 5) AND ((octet_length(timezone) >= 1) AND (octet_length(timezone) <= 255)) AND (timezone = btrim(timezone)) AND (timezone !~ '[[:cntrl:]]'::text)))
);

CREATE TABLE github_schedule_registry_revisions (
    registry_id uuid NOT NULL,
    discovery_id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid CONSTRAINT github_schedule_registry_revisi_provider_connection_id_not_null NOT NULL,
    manifest_revision bigint NOT NULL,
    manifest_digest bytea NOT NULL,
    github_repository_owner_id bigint CONSTRAINT github_schedule_registry_re_github_repository_owner_id_not_null NOT NULL,
    default_branch_ref text NOT NULL COLLATE pg_catalog."C",
    source_revision bytea NOT NULL,
    source_authority_kind text CONSTRAINT github_schedule_registry_revisio_source_authority_kind_not_null NOT NULL COLLATE pg_catalog."C",
    repository_contents_authority_id uuid NOT NULL,
    repository_contents_authority_identity_digest bytea NOT NULL,
    repository_contents_authority_app_configuration_revision bigint NOT NULL,
    repository_contents_authority_policy_revision bigint NOT NULL,
    archive_digest bytea NOT NULL,
    archive_object_key text NOT NULL COLLATE pg_catalog."C",
    archive_size_bytes bigint NOT NULL,
    archive_media_type text NOT NULL COLLATE pg_catalog."C",
    inventory_digest bytea NOT NULL,
    schedule_count smallint NOT NULL,
    discovered_at_ms bigint NOT NULL,
    CONSTRAINT github_schedule_registry_revisions_archive_shape CHECK ((((octet_length(archive_object_key) >= 1) AND (octet_length(archive_object_key) <= 1024)) AND (archive_object_key = btrim(archive_object_key)) AND (archive_object_key !~ '[[:cntrl:]]'::text) AND ((archive_size_bytes >= 1) AND (archive_size_bytes <= 268435456)) AND (archive_media_type = 'application/vnd.automata.github-repository-archive+gzip'::text))),
    CONSTRAINT github_schedule_registry_revisions_bounds CHECK (((manifest_revision > 0) AND (github_repository_owner_id > 0) AND ((schedule_count >= 0) AND (schedule_count <= 256)) AND (discovered_at_ms >= 0))),
    CONSTRAINT github_schedule_registry_revisions_digest_shape CHECK (((octet_length(manifest_digest) = 32) AND (octet_length(archive_digest) = 32) AND (octet_length(inventory_digest) = 32) AND (octet_length(repository_contents_authority_identity_digest) = 32))),
    CONSTRAINT github_schedule_registry_revisions_non_nil CHECK (((registry_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (discovery_id = registry_id))),
    CONSTRAINT github_schedule_registry_revisions_source_authority_shape CHECK ((source_authority_kind = 'repository_contents_read'::text) AND (repository_contents_authority_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_contents_authority_app_configuration_revision > 0) AND (repository_contents_authority_policy_revision > 0)),
    CONSTRAINT github_schedule_registry_revisions_source_shape CHECK (((default_branch_ref ~ '^refs/heads/[^[:cntrl:][:space:]]+$'::text) AND ((octet_length(default_branch_ref) >= 12) AND (octet_length(default_branch_ref) <= 1024)) AND (octet_length(source_revision) = ANY (ARRAY[20, 32])) AND (source_revision <> decode(repeat('00'::text, octet_length(source_revision)), 'hex'::text))))
);

CREATE TABLE github_schedule_registry_seals (
    registry_id uuid NOT NULL,
    inventory_digest bytea NOT NULL,
    schedule_count smallint NOT NULL,
    sealed_at_ms bigint NOT NULL,
    CONSTRAINT github_schedule_registry_seals_shape CHECK (((octet_length(inventory_digest) = 32) AND ((schedule_count >= 0) AND (schedule_count <= 256)) AND (sealed_at_ms >= 0)))
);

CREATE TABLE github_schedule_runtime (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    registry_id uuid NOT NULL,
    entry_ordinal smallint NOT NULL,
    next_fire_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT github_schedule_runtime_time CHECK (((next_fire_at_ms >= 0) AND (updated_at_ms >= 0)))
);

CREATE TABLE github_schedule_workflow_run_evidence (
    schedule_fire_id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    registry_id uuid NOT NULL,
    entry_ordinal smallint NOT NULL,
    scheduled_at_ms bigint NOT NULL,
    provider_manifest_revision bigint NOT NULL,
    provider_manifest_digest bytea NOT NULL,
    github_repository_owner_id bigint NOT NULL,
    workflow_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    run_id uuid NOT NULL,
    root_invocation_id uuid NOT NULL,
    admission_claim_owner_id uuid NOT NULL,
    admission_claim_attempt smallint NOT NULL,
    admission_claim_fence bigint NOT NULL,
    admission_claimed_at_ms bigint NOT NULL,
    admission_claim_expires_at_ms bigint NOT NULL,
    source_revision bytea NOT NULL,
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    source_digest bytea NOT NULL,
    event_name text NOT NULL COLLATE pg_catalog."C",
    event_digest bytea NOT NULL,
    git_ref text NOT NULL COLLATE pg_catalog."C",
    workflow_plan_schema smallint NOT NULL,
    plan_digest bytea NOT NULL,
    logical_admission_digest bytea NOT NULL,
    evidence_digest bytea GENERATED ALWAYS AS (automata_github_schedule_run_evidence_digest(schedule_fire_id, tenant_id, repository_id, provider_connection_id, registry_id, entry_ordinal, scheduled_at_ms, provider_manifest_revision, provider_manifest_digest, github_repository_owner_id, workflow_id, snapshot_id, run_id, root_invocation_id, admission_claim_owner_id, admission_claim_attempt, admission_claim_fence, admission_claimed_at_ms, admission_claim_expires_at_ms, source_revision, workflow_path, source_digest, event_name, event_digest, git_ref, workflow_plan_schema, plan_digest, logical_admission_digest, admitted_at_ms)) STORED,
    admitted_at_ms bigint NOT NULL,
    CONSTRAINT github_schedule_workflow_run_evidence_non_nil CHECK (schedule_fire_id <> '00000000-0000-0000-0000-000000000000'::uuid AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid AND provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid AND registry_id <> '00000000-0000-0000-0000-000000000000'::uuid AND workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid AND snapshot_id <> '00000000-0000-0000-0000-000000000000'::uuid AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid AND root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid AND admission_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT github_schedule_workflow_run_evidence_shape CHECK (entry_ordinal >= 0 AND entry_ordinal <= 255 AND scheduled_at_ms >= 0 AND provider_manifest_revision > 0 AND octet_length(provider_manifest_digest) = 32 AND github_repository_owner_id > 0 AND admission_claim_attempt >= 1 AND admission_claim_attempt <= 20 AND admission_claim_fence > 0 AND admission_claimed_at_ms >= 0 AND admission_claim_expires_at_ms > admission_claimed_at_ms AND admitted_at_ms >= admission_claimed_at_ms AND admitted_at_ms < admission_claim_expires_at_ms AND octet_length(source_revision) IN (20, 32) AND source_revision <> decode(repeat('00', octet_length(source_revision)), 'hex') AND octet_length(source_digest) = 32 AND event_name = 'schedule' AND octet_length(event_digest) = 32 AND automata_github_provider_git_ref_canonical(git_ref) AND workflow_plan_schema = 1 AND octet_length(plan_digest) = 32 AND octet_length(logical_admission_digest) = 32 AND octet_length(evidence_digest) = 32 AND workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$' AND workflow_path !~ '[[:cntrl:]\\]')
);

CREATE TABLE github_server_service_authority_handoffs (
    id uuid NOT NULL,
    tenant_id text NOT NULL,
    authority_id uuid NOT NULL,
    generation bigint NOT NULL,
    consumer_id uuid NOT NULL,
    consumer_owner_id uuid CONSTRAINT github_server_service_authority_hand_consumer_owner_id_not_null NOT NULL,
    consumer_claim_fence bigint CONSTRAINT github_server_service_authority_h_consumer_claim_fence_not_null NOT NULL,
    consumer_action text CONSTRAINT github_server_service_authority_handof_consumer_action_not_null NOT NULL COLLATE pg_catalog."C",
    consumer_revision bigint CONSTRAINT github_server_service_authority_hand_consumer_revision_not_null NOT NULL,
    required_through_ms bigint CONSTRAINT github_server_service_authority_ha_required_through_ms_not_null NOT NULL,
    granted_at_ms bigint NOT NULL,
    released_at_ms bigint,
    CONSTRAINT github_server_service_handoffs_action CHECK ((consumer_action = ANY (ARRAY['ensure_check_suite'::text, 'create_check_run'::text, 'reconcile_check_run'::text, 'publish_check_run'::text, 'fetch_repository_revision'::text, 'fetch_repository_changed_files'::text, 'discover_repository_schedules'::text]))),
    CONSTRAINT github_server_service_handoffs_non_nil CHECK (((id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (consumer_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (consumer_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT github_server_service_handoffs_positive CHECK (((generation > 0) AND (consumer_claim_fence > 0) AND (consumer_revision > 0))),
    CONSTRAINT github_server_service_handoffs_time_shape CHECK (((granted_at_ms >= 0) AND (required_through_ms > granted_at_ms) AND ((required_through_ms - granted_at_ms) <=
CASE consumer_action
    WHEN 'publish_check_run'::text THEN 1500000
    ELSE 1200000
END) AND ((released_at_ms IS NULL) OR (released_at_ms >= granted_at_ms))))
);

CREATE TABLE github_server_service_authority_issuances (
    tenant_id text NOT NULL,
    authority_id uuid NOT NULL,
    generation bigint NOT NULL,
    state text NOT NULL COLLATE pg_catalog."C",
    mint_attempt_count smallint CONSTRAINT github_server_service_authority_iss_mint_attempt_count_not_null NOT NULL,
    mint_claim_fence bigint CONSTRAINT github_server_service_authority_issua_mint_claim_fence_not_null NOT NULL,
    mint_claim_owner_id uuid,
    mint_claimed_at_ms bigint,
    mint_claim_expires_at_ms bigint,
    mint_started_at_ms bigint,
    mint_started_owner_id uuid,
    mint_started_claim_fence bigint,
    mint_started_claimed_at_ms bigint,
    mint_started_claim_expires_at_ms bigint,
    ready_at_ms bigint,
    generation_failure_gate_at_ms bigint,
    next_mint_at_ms bigint,
    mint_failure_kind text COLLATE pg_catalog."C",
    requested_at_ms bigint CONSTRAINT github_server_service_authority_issuan_requested_at_ms_not_null NOT NULL,
    request_deadline_at_ms bigint CONSTRAINT github_server_service_authority_request_deadline_at_ms_not_null NOT NULL,
    conservative_expiry_at_ms bigint CONSTRAINT github_server_service_author_conservative_expiry_at_ms_not_null NOT NULL,
    provider_expires_at_ms bigint,
    safe_erase_after_ms bigint CONSTRAINT github_server_service_authority_is_safe_erase_after_ms_not_null NOT NULL,
    plaintext_schema smallint,
    plaintext_size_bytes bigint,
    plaintext_digest bytea,
    aad_digest bytea,
    envelope_schema smallint,
    wrapping_key_id text COLLATE pg_catalog."C",
    wrapped_data_key bytea,
    nonce bytea,
    ciphertext bytea,
    revoke_attempt_count smallint DEFAULT 0 CONSTRAINT github_server_service_authority_i_revoke_attempt_count_not_null NOT NULL,
    revoke_claim_fence bigint DEFAULT 0 CONSTRAINT github_server_service_authority_iss_revoke_claim_fence_not_null NOT NULL,
    revoke_claim_owner_id uuid,
    revoke_claimed_at_ms bigint,
    revoke_claim_expires_at_ms bigint,
    revoke_result_owner_id uuid,
    revoke_result_claim_fence bigint,
    revoke_result_claimed_at_ms bigint,
    revoke_result_claim_expires_at_ms bigint,
    next_revoke_at_ms bigint,
    revoke_failure_kind text COLLATE pg_catalog."C",
    terminal_reason text COLLATE pg_catalog."C",
    created_at_ms bigint CONSTRAINT github_server_service_authority_issuance_created_at_ms_not_null NOT NULL,
    state_updated_at_ms bigint CONSTRAINT github_server_service_authority_is_state_updated_at_ms_not_null NOT NULL,
    CONSTRAINT github_server_service_issuances_claim_owner_non_nil CHECK ((((mint_claim_owner_id IS NULL) OR (mint_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((mint_started_owner_id IS NULL) OR (mint_started_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((revoke_claim_owner_id IS NULL) OR (revoke_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((revoke_result_owner_id IS NULL) OR (revoke_result_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT github_server_service_issuances_failure_shape CHECK ((((mint_failure_kind IS NULL) OR (((octet_length(mint_failure_kind) >= 1) AND (octet_length(mint_failure_kind) <= 128)) AND ((mint_failure_kind ~ '^[a-z0-9]$'::text) OR (mint_failure_kind ~ '^[a-z0-9][a-z0-9_.:-]*[a-z0-9]$'::text)))) AND ((revoke_failure_kind IS NULL) OR (((octet_length(revoke_failure_kind) >= 1) AND (octet_length(revoke_failure_kind) <= 128)) AND ((revoke_failure_kind ~ '^[a-z0-9]$'::text) OR (revoke_failure_kind ~ '^[a-z0-9][a-z0-9_.:-]*[a-z0-9]$'::text)))))),
    CONSTRAINT github_server_service_issuances_generation_failure_gate_shape CHECK (((((generation_failure_gate_at_ms IS NULL) AND (state = ANY (ARRAY['claimed'::text, 'minting'::text, 'mint_retry'::text, 'ready'::text]))) OR ((state = 'rejected'::text) AND (generation_failure_gate_at_ms IS NOT NULL) AND (generation_failure_gate_at_ms >= created_at_ms)) OR ((state = 'indeterminate'::text) AND (generation_failure_gate_at_ms IS NOT NULL) AND (generation_failure_gate_at_ms >= created_at_ms) AND (generation_failure_gate_at_ms <= safe_erase_after_ms)) OR ((state = ANY (ARRAY['revoke_pending'::text, 'revoke_claimed'::text, 'revoke_retry'::text, 'quarantined'::text, 'revoked'::text])) AND ((generation_failure_gate_at_ms IS NULL) OR ((generation_failure_gate_at_ms >= created_at_ms) AND (generation_failure_gate_at_ms <= safe_erase_after_ms))))) IS TRUE)),
    CONSTRAINT github_server_service_issuances_generation_positive CHECK ((generation > 0)),
    CONSTRAINT github_server_service_issuances_mint_attempt_bound CHECK ((((mint_attempt_count >= 1) AND (mint_attempt_count <= 32)) AND ((mint_claim_fence >= 1) AND (mint_claim_fence <= '9223372036854775807'::bigint)) AND (mint_claim_fence = mint_attempt_count))),
    CONSTRAINT github_server_service_issuances_mint_started_provenance_shape CHECK ((((mint_started_at_ms IS NULL) AND (mint_started_owner_id IS NULL) AND (mint_started_claim_fence IS NULL) AND (mint_started_claimed_at_ms IS NULL) AND (mint_started_claim_expires_at_ms IS NULL)) OR ((mint_started_at_ms IS NOT NULL) AND (mint_started_owner_id IS NOT NULL) AND (mint_started_claim_fence IS NOT NULL) AND (mint_started_claimed_at_ms IS NOT NULL) AND (mint_started_claim_expires_at_ms IS NOT NULL) AND (mint_started_claim_fence = mint_claim_fence) AND (mint_started_claimed_at_ms >= requested_at_ms) AND (mint_started_at_ms >= mint_started_claimed_at_ms) AND (mint_started_claim_expires_at_ms > mint_started_at_ms) AND ((mint_started_claim_expires_at_ms - mint_started_claimed_at_ms) <= 120000) AND (mint_started_claim_expires_at_ms <= request_deadline_at_ms)))),
    CONSTRAINT github_server_service_issuances_protected_shape CHECK ((((plaintext_schema IS NULL) AND (plaintext_size_bytes IS NULL) AND (plaintext_digest IS NULL) AND (aad_digest IS NULL) AND (envelope_schema IS NULL) AND (wrapping_key_id IS NULL) AND (wrapped_data_key IS NULL) AND (nonce IS NULL) AND (ciphertext IS NULL)) OR ((plaintext_schema IS NOT NULL) AND (plaintext_size_bytes IS NOT NULL) AND (plaintext_digest IS NOT NULL) AND (aad_digest IS NOT NULL) AND (envelope_schema IS NOT NULL) AND (wrapping_key_id IS NOT NULL) AND (wrapped_data_key IS NOT NULL) AND (nonce IS NOT NULL) AND (ciphertext IS NOT NULL) AND (plaintext_schema = 1) AND ((plaintext_size_bytes >= 1) AND (plaintext_size_bytes <= 16384)) AND (octet_length(plaintext_digest) = 32) AND (octet_length(aad_digest) = 32) AND (envelope_schema = 1) AND ((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 64)) AND (wrapping_key_id ~ '^[a-z0-9][a-z0-9._-]*[a-z0-9]$|^[a-z0-9]$'::text) AND ((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 65536)) AND (octet_length(nonce) = 12) AND (octet_length(ciphertext) = (plaintext_size_bytes + 16))))),
    CONSTRAINT github_server_service_issuances_provider_expiry_exact CHECK (((((provider_expires_at_ms IS NULL) AND (safe_erase_after_ms = conservative_expiry_at_ms)) OR ((provider_expires_at_ms IS NOT NULL) AND (provider_expires_at_ms > requested_at_ms) AND ((provider_expires_at_ms)::numeric <= ((request_deadline_at_ms)::numeric + (3660000)::numeric)) AND ((safe_erase_after_ms)::numeric = ((provider_expires_at_ms)::numeric + (120000)::numeric)) AND (safe_erase_after_ms <= conservative_expiry_at_ms))) IS TRUE)),
    CONSTRAINT github_server_service_issuances_ready_evidence_exact CHECK (((((ready_at_ms IS NULL) OR ((mint_started_at_ms IS NOT NULL) AND (ready_at_ms >= mint_started_at_ms) AND (ready_at_ms <= state_updated_at_ms))) AND (((state = 'ready'::text) AND (ready_at_ms = state_updated_at_ms)) OR ((state = ANY (ARRAY['claimed'::text, 'minting'::text, 'mint_retry'::text, 'indeterminate'::text, 'rejected'::text])) AND (ready_at_ms IS NULL)) OR (state = ANY (ARRAY['revoke_pending'::text, 'revoke_claimed'::text, 'revoke_retry'::text, 'quarantined'::text, 'revoked'::text])))) IS TRUE)),
    CONSTRAINT github_server_service_issuances_request_horizon_exact CHECK (((requested_at_ms >= 0) AND (request_deadline_at_ms > requested_at_ms) AND ((request_deadline_at_ms - requested_at_ms) <= 120000) AND ((conservative_expiry_at_ms)::numeric = ((request_deadline_at_ms)::numeric + (3780000)::numeric)) AND (safe_erase_after_ms <= conservative_expiry_at_ms) AND (created_at_ms = requested_at_ms) AND (state_updated_at_ms >= created_at_ms) AND ((mint_started_at_ms IS NULL) OR ((mint_started_at_ms >= requested_at_ms) AND (mint_started_at_ms < request_deadline_at_ms))))),
    CONSTRAINT github_server_service_issuances_revoke_attempt_bound CHECK ((((revoke_attempt_count >= 0) AND (revoke_attempt_count <= 64)) AND ((revoke_claim_fence >= 0) AND (revoke_claim_fence <= '9223372036854775807'::bigint)) AND (revoke_claim_fence = revoke_attempt_count))),
    CONSTRAINT github_server_service_issuances_revoke_result_provenance_shape CHECK ((((revoke_result_owner_id IS NULL) AND (revoke_result_claim_fence IS NULL) AND (revoke_result_claimed_at_ms IS NULL) AND (revoke_result_claim_expires_at_ms IS NULL)) OR ((revoke_result_owner_id IS NOT NULL) AND (revoke_result_claim_fence IS NOT NULL) AND (revoke_result_claimed_at_ms IS NOT NULL) AND (revoke_result_claim_expires_at_ms IS NOT NULL) AND (revoke_result_claim_fence = revoke_claim_fence) AND (revoke_result_claim_fence > 0) AND (revoke_result_claimed_at_ms >= requested_at_ms) AND (revoke_result_claim_expires_at_ms > revoke_result_claimed_at_ms) AND ((revoke_result_claim_expires_at_ms - revoke_result_claimed_at_ms) <= 120000) AND (revoke_result_claim_expires_at_ms <= safe_erase_after_ms) AND (state = ANY (ARRAY['revoke_retry'::text, 'quarantined'::text, 'revoked'::text])) AND ((state <> 'revoke_retry'::text) OR (revoke_result_owner_id IS NOT NULL)) AND ((state <> 'quarantined'::text) OR ((revoke_attempt_count = 0) AND (revoke_result_owner_id IS NULL)) OR ((revoke_attempt_count > 0) AND (revoke_result_owner_id IS NOT NULL))) AND ((state <> 'revoked'::text) OR (terminal_reason <> 'provider_revoked'::text) OR (revoke_result_owner_id IS NOT NULL))))),
    CONSTRAINT github_server_service_issuances_state CHECK ((state = ANY (ARRAY['claimed'::text, 'minting'::text, 'mint_retry'::text, 'indeterminate'::text, 'ready'::text, 'revoke_pending'::text, 'revoke_claimed'::text, 'revoke_retry'::text, 'quarantined'::text, 'rejected'::text, 'revoked'::text]))),
    CONSTRAINT github_server_service_issuances_state_shape CHECK (((((state = 'claimed'::text) AND (mint_claim_owner_id IS NOT NULL) AND (mint_claimed_at_ms IS NOT NULL) AND (mint_claim_expires_at_ms IS NOT NULL) AND (mint_claimed_at_ms >= requested_at_ms) AND (mint_claimed_at_ms = state_updated_at_ms) AND (mint_claim_expires_at_ms > mint_claimed_at_ms) AND ((mint_claim_expires_at_ms - mint_claimed_at_ms) <= 120000) AND (mint_claim_expires_at_ms <= request_deadline_at_ms) AND (mint_started_at_ms IS NULL) AND (next_mint_at_ms IS NULL) AND (mint_failure_kind IS NULL) AND (provider_expires_at_ms IS NULL) AND (plaintext_schema IS NULL) AND (plaintext_size_bytes IS NULL) AND (plaintext_digest IS NULL) AND (aad_digest IS NULL) AND (envelope_schema IS NULL) AND (wrapping_key_id IS NULL) AND (wrapped_data_key IS NULL) AND (nonce IS NULL) AND (ciphertext IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (revoke_claimed_at_ms IS NULL) AND (revoke_claim_expires_at_ms IS NULL) AND (next_revoke_at_ms IS NULL) AND (revoke_failure_kind IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'minting'::text) AND (mint_claim_owner_id IS NOT NULL) AND (mint_claimed_at_ms IS NOT NULL) AND (mint_claim_expires_at_ms IS NOT NULL) AND (mint_started_at_ms IS NOT NULL) AND (mint_claimed_at_ms >= requested_at_ms) AND (mint_claim_expires_at_ms > mint_started_at_ms) AND ((mint_claim_expires_at_ms - mint_claimed_at_ms) <= 120000) AND (mint_started_at_ms >= mint_claimed_at_ms) AND (mint_started_at_ms < request_deadline_at_ms) AND (state_updated_at_ms = mint_started_at_ms) AND (next_mint_at_ms IS NULL) AND (mint_failure_kind IS NULL) AND (provider_expires_at_ms IS NULL) AND (plaintext_schema IS NULL) AND (plaintext_size_bytes IS NULL) AND (plaintext_digest IS NULL) AND (aad_digest IS NULL) AND (envelope_schema IS NULL) AND (wrapping_key_id IS NULL) AND (wrapped_data_key IS NULL) AND (nonce IS NULL) AND (ciphertext IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (revoke_claimed_at_ms IS NULL) AND (revoke_claim_expires_at_ms IS NULL) AND (next_revoke_at_ms IS NULL) AND (revoke_failure_kind IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'mint_retry'::text) AND ((mint_attempt_count >= 1) AND (mint_attempt_count <= 31)) AND (mint_claim_owner_id IS NULL) AND (mint_claimed_at_ms IS NULL) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NOT NULL) AND (next_mint_at_ms > state_updated_at_ms) AND ((next_mint_at_ms - state_updated_at_ms) <= 120000) AND (next_mint_at_ms < request_deadline_at_ms) AND (mint_failure_kind IS NOT NULL) AND (provider_expires_at_ms IS NULL) AND (plaintext_schema IS NULL) AND (plaintext_size_bytes IS NULL) AND (plaintext_digest IS NULL) AND (aad_digest IS NULL) AND (envelope_schema IS NULL) AND (wrapping_key_id IS NULL) AND (wrapped_data_key IS NULL) AND (nonce IS NULL) AND (ciphertext IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (revoke_claimed_at_ms IS NULL) AND (revoke_claim_expires_at_ms IS NULL) AND (next_revoke_at_ms IS NULL) AND (revoke_failure_kind IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'indeterminate'::text) AND (mint_claim_owner_id IS NULL) AND (mint_claimed_at_ms IS NULL) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (mint_failure_kind IS NOT NULL) AND (provider_expires_at_ms IS NULL) AND (plaintext_schema IS NULL) AND (plaintext_size_bytes IS NULL) AND (plaintext_digest IS NULL) AND (aad_digest IS NULL) AND (envelope_schema IS NULL) AND (wrapping_key_id IS NULL) AND (wrapped_data_key IS NULL) AND (nonce IS NULL) AND (ciphertext IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (revoke_claimed_at_ms IS NULL) AND (revoke_claim_expires_at_ms IS NULL) AND (next_revoke_at_ms IS NULL) AND (revoke_failure_kind IS NULL) AND (terminal_reason IS NULL)) OR ((state = ANY (ARRAY['ready'::text, 'revoke_pending'::text])) AND (mint_claim_owner_id IS NULL) AND (mint_claimed_at_ms IS NULL) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (((state = 'ready'::text) AND (mint_failure_kind IS NULL) AND (provider_expires_at_ms IS NOT NULL)) OR ((state = 'revoke_pending'::text) AND (((provider_expires_at_ms IS NOT NULL) AND (mint_failure_kind IS NULL)) OR ((provider_expires_at_ms IS NULL) AND (mint_failure_kind = 'provider_expiry_unknown'::text))))) AND (plaintext_schema IS NOT NULL) AND (plaintext_size_bytes IS NOT NULL) AND (plaintext_digest IS NOT NULL) AND (aad_digest IS NOT NULL) AND (envelope_schema IS NOT NULL) AND (wrapping_key_id IS NOT NULL) AND (wrapped_data_key IS NOT NULL) AND (nonce IS NOT NULL) AND (ciphertext IS NOT NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (revoke_claimed_at_ms IS NULL) AND (revoke_claim_expires_at_ms IS NULL) AND (next_revoke_at_ms IS NULL) AND (revoke_failure_kind IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'revoke_claimed'::text) AND (mint_claim_owner_id IS NULL) AND (mint_claimed_at_ms IS NULL) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (((provider_expires_at_ms IS NOT NULL) AND (mint_failure_kind IS NULL)) OR ((provider_expires_at_ms IS NULL) AND (mint_failure_kind = 'provider_expiry_unknown'::text))) AND (plaintext_schema IS NOT NULL) AND (plaintext_size_bytes IS NOT NULL) AND (plaintext_digest IS NOT NULL) AND (aad_digest IS NOT NULL) AND (envelope_schema IS NOT NULL) AND (wrapping_key_id IS NOT NULL) AND (wrapped_data_key IS NOT NULL) AND (nonce IS NOT NULL) AND (ciphertext IS NOT NULL) AND ((revoke_attempt_count >= 1) AND (revoke_attempt_count <= 64)) AND (revoke_claim_fence > 0) AND (revoke_claim_owner_id IS NOT NULL) AND (revoke_claimed_at_ms IS NOT NULL) AND (revoke_claim_expires_at_ms IS NOT NULL) AND (revoke_claimed_at_ms = state_updated_at_ms) AND (revoke_claim_expires_at_ms > revoke_claimed_at_ms) AND ((revoke_claim_expires_at_ms - revoke_claimed_at_ms) <= 120000) AND (revoke_claim_expires_at_ms <= safe_erase_after_ms) AND (next_revoke_at_ms IS NULL) AND (revoke_failure_kind IS NULL) AND (terminal_reason IS NULL)) OR ((state = 'revoke_retry'::text) AND (mint_claim_owner_id IS NULL) AND (mint_claimed_at_ms IS NULL) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (((provider_expires_at_ms IS NOT NULL) AND (mint_failure_kind IS NULL)) OR ((provider_expires_at_ms IS NULL) AND (mint_failure_kind = 'provider_expiry_unknown'::text))) AND (plaintext_schema IS NOT NULL) AND (plaintext_size_bytes IS NOT NULL) AND (plaintext_digest IS NOT NULL) AND (aad_digest IS NOT NULL) AND (envelope_schema IS NOT NULL) AND (wrapping_key_id IS NOT NULL) AND (wrapped_data_key IS NOT NULL) AND (nonce IS NOT NULL) AND (ciphertext IS NOT NULL) AND ((revoke_attempt_count >= 1) AND (revoke_attempt_count <= 63)) AND (revoke_claim_fence > 0) AND (revoke_claim_owner_id IS NULL) AND (revoke_claimed_at_ms IS NULL) AND (revoke_claim_expires_at_ms IS NULL) AND (next_revoke_at_ms IS NOT NULL) AND (next_revoke_at_ms > state_updated_at_ms) AND ((next_revoke_at_ms - state_updated_at_ms) <= 86400000) AND (next_revoke_at_ms < safe_erase_after_ms) AND (revoke_failure_kind IS NOT NULL) AND (terminal_reason IS NULL)) OR ((state = 'quarantined'::text) AND (mint_claim_owner_id IS NULL) AND (mint_claimed_at_ms IS NULL) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (((provider_expires_at_ms IS NOT NULL) AND (mint_failure_kind IS NULL)) OR ((provider_expires_at_ms IS NULL) AND (mint_failure_kind = 'provider_expiry_unknown'::text))) AND (plaintext_schema IS NOT NULL) AND (plaintext_size_bytes IS NOT NULL) AND (plaintext_digest IS NOT NULL) AND (aad_digest IS NOT NULL) AND (envelope_schema IS NOT NULL) AND (wrapping_key_id IS NOT NULL) AND (wrapped_data_key IS NOT NULL) AND (nonce IS NOT NULL) AND (ciphertext IS NOT NULL) AND ((revoke_attempt_count >= 0) AND (revoke_attempt_count <= 64)) AND (revoke_claim_owner_id IS NULL) AND (revoke_claimed_at_ms IS NULL) AND (revoke_claim_expires_at_ms IS NULL) AND (next_revoke_at_ms IS NULL) AND (revoke_failure_kind IS NOT NULL) AND (terminal_reason IS NULL)) OR ((state = 'rejected'::text) AND (mint_claim_owner_id IS NULL) AND (mint_claimed_at_ms IS NULL) AND (mint_claim_expires_at_ms IS NULL) AND ((mint_started_at_ms IS NULL) OR ((mint_started_at_ms >= requested_at_ms) AND (mint_started_at_ms < request_deadline_at_ms))) AND (next_mint_at_ms IS NULL) AND (mint_failure_kind IS NOT NULL) AND (provider_expires_at_ms IS NULL) AND (plaintext_schema IS NULL) AND (plaintext_size_bytes IS NULL) AND (plaintext_digest IS NULL) AND (aad_digest IS NULL) AND (envelope_schema IS NULL) AND (wrapping_key_id IS NULL) AND (wrapped_data_key IS NULL) AND (nonce IS NULL) AND (ciphertext IS NULL) AND (revoke_attempt_count = 0) AND (revoke_claim_fence = 0) AND (revoke_claim_owner_id IS NULL) AND (revoke_claimed_at_ms IS NULL) AND (revoke_claim_expires_at_ms IS NULL) AND (next_revoke_at_ms IS NULL) AND (revoke_failure_kind IS NULL) AND (terminal_reason IS NOT NULL) AND (terminal_reason = ANY (ARRAY['request_expired'::text, 'provider_rejected'::text, 'retry_exhausted'::text, 'authority_retired_before_mint'::text])) AND ((terminal_reason = ANY (ARRAY['request_expired'::text, 'authority_retired_before_mint'::text])) OR ((terminal_reason = ANY (ARRAY['provider_rejected'::text, 'retry_exhausted'::text])) AND (mint_started_at_ms IS NOT NULL)))) OR ((state = 'revoked'::text) AND (mint_claim_owner_id IS NULL) AND (mint_claimed_at_ms IS NULL) AND (mint_claim_expires_at_ms IS NULL) AND (mint_started_at_ms IS NOT NULL) AND (next_mint_at_ms IS NULL) AND (((terminal_reason = 'conservative_expiry'::text) AND (provider_expires_at_ms IS NULL) AND (mint_failure_kind IS NOT NULL)) OR ((terminal_reason = 'provider_expired'::text) AND (provider_expires_at_ms IS NOT NULL) AND (mint_failure_kind IS NULL)) OR ((terminal_reason = 'provider_revoked'::text) AND (((provider_expires_at_ms IS NOT NULL) AND (mint_failure_kind IS NULL)) OR ((provider_expires_at_ms IS NULL) AND (mint_failure_kind = 'provider_expiry_unknown'::text))))) AND (plaintext_schema IS NULL) AND (plaintext_size_bytes IS NULL) AND (plaintext_digest IS NULL) AND (aad_digest IS NULL) AND (envelope_schema IS NULL) AND (wrapping_key_id IS NULL) AND (wrapped_data_key IS NULL) AND (nonce IS NULL) AND (ciphertext IS NULL) AND (revoke_claim_owner_id IS NULL) AND (revoke_claimed_at_ms IS NULL) AND (revoke_claim_expires_at_ms IS NULL) AND (next_revoke_at_ms IS NULL) AND (revoke_failure_kind IS NULL) AND (terminal_reason IS NOT NULL) AND (terminal_reason = ANY (ARRAY['provider_revoked'::text, 'provider_expired'::text, 'conservative_expiry'::text])))) IS TRUE))
);

CREATE TABLE github_team_membership_observations (
    tenant_id text NOT NULL,
    snapshot_id uuid NOT NULL,
    organization_id bigint NOT NULL,
    team_id bigint NOT NULL,
    team_slug text NOT NULL,
    CONSTRAINT github_team_membership_observations_id_positive CHECK ((team_id > 0)),
    CONSTRAINT github_team_membership_observations_slug_shape CHECK ((((octet_length(team_slug) >= 1) AND (octet_length(team_slug) <= 255)) AND (team_slug !~ '[[:space:][:cntrl:]]'::text)))
);

CREATE TABLE github_workflow_rerun_subject_evidence (
    operation_id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    run_id uuid NOT NULL,
    source_run_id uuid NOT NULL,
    root_invocation_id uuid CONSTRAINT github_workflow_rerun_subject_evide_root_invocation_id_not_null NOT NULL,
    github_repository_owner_id bigint CONSTRAINT github_workflow_rerun_subje_github_repository_owner_id_not_null NOT NULL,
    github_check_subject_id uuid CONSTRAINT github_workflow_rerun_subject__github_check_subject_id_not_null NOT NULL,
    github_check_head_sha bytea CONSTRAINT github_workflow_rerun_subject_ev_github_check_head_sha_not_null NOT NULL,
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    source_digest bytea NOT NULL,
    event_name text NOT NULL COLLATE pg_catalog."C",
    event_digest bytea NOT NULL,
    git_ref text NOT NULL COLLATE pg_catalog."C",
    workflow_plan_schema smallint CONSTRAINT github_workflow_rerun_subject_evi_workflow_plan_schema_not_null NOT NULL,
    plan_digest bytea NOT NULL,
    logical_admission_digest bytea CONSTRAINT github_workflow_rerun_subject_logical_admission_digest_not_null NOT NULL,
    admitted_at_ms bigint NOT NULL,
    subject_evidence_sha256 bytea GENERATED ALWAYS AS (automata_github_workflow_rerun_subject_evidence_digest(operation_id, tenant_id, repository_id, workflow_id, snapshot_id, run_id, source_run_id, root_invocation_id, github_repository_owner_id, github_check_subject_id, github_check_head_sha, workflow_path, source_digest, event_name, event_digest, git_ref, workflow_plan_schema, plan_digest, logical_admission_digest, admitted_at_ms)) STORED,
    CONSTRAINT github_workflow_rerun_subject_evidence_non_nil CHECK (((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (snapshot_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (github_check_subject_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT github_workflow_rerun_subject_evidence_shape CHECK (((github_repository_owner_id > 0) AND (octet_length(github_check_head_sha) = 20) AND (github_check_head_sha <> decode(repeat('00'::text, 20), 'hex'::text)) AND (octet_length(source_digest) = 32) AND ((octet_length(event_name) >= 1) AND (octet_length(event_name) <= 1024)) AND (event_name !~ '[[:cntrl:]]'::text) AND (octet_length(event_digest) = 32) AND automata_github_provider_git_ref_canonical(git_ref) AND (workflow_plan_schema = 1) AND (octet_length(plan_digest) = 32) AND (octet_length(logical_admission_digest) = 32) AND (admitted_at_ms >= 0) AND (octet_length(subject_evidence_sha256) = 32) AND (workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'::text) AND (workflow_path !~ '[[:cntrl:]\\]'::text)))
);

CREATE TABLE github_workflow_run_subject_evidence (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    run_id uuid NOT NULL,
    root_invocation_id uuid CONSTRAINT github_workflow_run_subject_evidenc_root_invocation_id_not_null NOT NULL,
    provider_delivery_id uuid CONSTRAINT github_workflow_run_subject_evide_provider_delivery_id_not_null NOT NULL,
    provider_delivery_idempotency_key text CONSTRAINT github_workflow_run_subject_provider_delivery_idempote_not_null NOT NULL COLLATE pg_catalog."C",
    admission_claim_owner_id uuid CONSTRAINT github_workflow_run_subject_e_admission_claim_owner_id_not_null NOT NULL,
    admission_claim_attempt smallint CONSTRAINT github_workflow_run_subject_ev_admission_claim_attempt_not_null NOT NULL,
    admission_claim_fence bigint CONSTRAINT github_workflow_run_subject_evid_admission_claim_fence_not_null NOT NULL,
    admission_claimed_at_ms bigint CONSTRAINT github_workflow_run_subject_ev_admission_claimed_at_ms_not_null NOT NULL,
    admission_claim_expires_at_ms bigint CONSTRAINT github_workflow_run_subject_admission_claim_expires_at_not_null NOT NULL,
    github_check_subject_id uuid CONSTRAINT github_workflow_run_subject_ev_github_check_subject_id_not_null NOT NULL,
    github_check_head_sha bytea CONSTRAINT github_workflow_run_subject_evid_github_check_head_sha_not_null NOT NULL,
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    source_digest bytea NOT NULL,
    event_name text NOT NULL COLLATE pg_catalog."C",
    event_digest bytea NOT NULL,
    git_ref text NOT NULL COLLATE pg_catalog."C",
    workflow_plan_schema smallint CONSTRAINT github_workflow_run_subject_evide_workflow_plan_schema_not_null NOT NULL,
    plan_digest bytea NOT NULL,
    logical_admission_digest bytea CONSTRAINT github_workflow_run_subject_e_logical_admission_digest_not_null NOT NULL,
    subject_evidence_sha256 bytea CONSTRAINT github_workflow_run_subject_ev_subject_evidence_sha256_not_null NOT NULL,
    admitted_at_ms bigint NOT NULL,
    CONSTRAINT github_workflow_run_subject_evidence_digest_shape CHECK (((octet_length(github_check_head_sha) = 20) AND (github_check_head_sha <> decode(repeat('00'::text, 20), 'hex'::text)) AND (octet_length(source_digest) = 32) AND (octet_length(event_digest) = 32) AND (octet_length(plan_digest) = 32) AND (octet_length(logical_admission_digest) = 32) AND (octet_length(subject_evidence_sha256) = 32))),
    CONSTRAINT github_workflow_run_subject_evidence_non_nil CHECK (((repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (snapshot_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_delivery_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (admission_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (github_check_subject_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT github_workflow_run_subject_evidence_selector_shape CHECK ((((octet_length(provider_delivery_idempotency_key) >= 1) AND (octet_length(provider_delivery_idempotency_key) <= 1024)) AND (provider_delivery_idempotency_key !~ '[[:cntrl:]]'::text) AND ((octet_length(workflow_path) >= 1) AND (octet_length(workflow_path) <= 1024)) AND (btrim(workflow_path) = workflow_path) AND (workflow_path !~ '[[:cntrl:]\\]'::text) AND ("left"(workflow_path, 1) <> '/'::text) AND (workflow_path !~ '(^|/)(\.|\.\.)(/|$)'::text) AND (workflow_path !~ '//'::text) AND ((octet_length(event_name) >= 1) AND (octet_length(event_name) <= 1024)) AND (event_name !~ '[[:cntrl:]]'::text) AND ((octet_length(git_ref) >= 6) AND (octet_length(git_ref) <= 1024)) AND (git_ref ~~ 'refs/%'::text) AND (git_ref !~ '[[:cntrl:]]'::text) AND (workflow_plan_schema = 1))),
    CONSTRAINT github_workflow_run_subject_evidence_time CHECK ((((admission_claim_attempt >= 1) AND (admission_claim_attempt <= 16)) AND (admission_claim_fence > 0) AND (admission_claimed_at_ms >= 0) AND (admission_claim_expires_at_ms > admission_claimed_at_ms) AND ((admission_claim_expires_at_ms - admission_claimed_at_ms) <= 3600000) AND (admitted_at_ms >= admission_claimed_at_ms) AND (admitted_at_ms < admission_claim_expires_at_ms)))
);

CREATE VIEW github_workflow_run_base_manifest_origins AS
 SELECT delivery_run.tenant_id,
    delivery_run.repository_id,
    delivery_run.workflow_id,
    delivery_run.snapshot_id,
    delivery_run.run_id,
    delivery_run.root_invocation_id,
    'provider_delivery'::text AS origin_kind,
    delivery_run.provider_delivery_id AS origin_id,
    'provider_delivery'::text AS admission_idempotency_kind,
    delivery_run.provider_delivery_idempotency_key AS admission_idempotency_key,
    delivery_run.github_check_subject_id,
    delivery_run.github_check_head_sha,
    delivery_run.workflow_path,
    delivery_run.source_digest,
    delivery_run.event_name,
    delivery_run.event_digest,
    delivery_run.git_ref,
    delivery_run.workflow_plan_schema,
    delivery_run.plan_digest,
    delivery_run.logical_admission_digest,
    delivery_run.admitted_at_ms,
    delivery_run.subject_evidence_sha256,
    delivery.provider_connection_id,
    delivery.provider_installation_id,
    delivery.github_repository_id,
    delivery.github_repository_owner_id,
    delivery.github_repository_name,
    delivery.repository_visibility,
    delivery.provider_manifest_revision,
    delivery.provider_manifest_digest,
    delivery.authenticated_webhook_verifier_fingerprint_sha256,
    delivery.authenticated_webhook_verifier_revision,
    delivery.checks_authority_id,
    delivery.checks_authority_identity_digest,
    delivery.checks_authority_app_configuration_revision,
    delivery.checks_authority_policy_revision,
    delivery.repository_contents_authority_id,
    delivery.repository_contents_authority_identity_digest,
    delivery.repository_contents_authority_app_configuration_revision,
    delivery.repository_contents_authority_policy_revision
   FROM (github_workflow_run_subject_evidence delivery_run
     JOIN github_provider_delivery_evidence delivery ON (((delivery.tenant_id = delivery_run.tenant_id) AND (delivery.repository_id = delivery_run.repository_id) AND (delivery.provider_delivery_id = delivery_run.provider_delivery_id))))
UNION ALL
 SELECT schedule_run.tenant_id,
    schedule_run.repository_id,
    schedule_run.workflow_id,
    schedule_run.snapshot_id,
    schedule_run.run_id,
    schedule_run.root_invocation_id,
    'scheduled_fire'::text AS origin_kind,
    schedule_run.schedule_fire_id AS origin_id,
    'operation'::text AS admission_idempotency_kind,
    (schedule_run.schedule_fire_id)::text AS admission_idempotency_key,
    NULL::uuid AS github_check_subject_id,
    schedule_run.source_revision AS github_check_head_sha,
    schedule_run.workflow_path,
    schedule_run.source_digest,
    schedule_run.event_name,
    schedule_run.event_digest,
    schedule_run.git_ref,
    schedule_run.workflow_plan_schema,
    schedule_run.plan_digest,
    schedule_run.logical_admission_digest,
    schedule_run.admitted_at_ms,
    schedule_run.evidence_digest AS subject_evidence_sha256,
    schedule_run.provider_connection_id,
    manifest.provider_installation_id,
    manifest.github_repository_id,
    schedule_run.github_repository_owner_id,
    manifest.github_repository_name,
    manifest.repository_visibility,
    schedule_run.provider_manifest_revision,
    schedule_run.provider_manifest_digest,
    manifest.webhook_verifier_fingerprint_sha256 AS authenticated_webhook_verifier_fingerprint_sha256,
    manifest.webhook_verifier_revision AS authenticated_webhook_verifier_revision,
    NULL::uuid AS checks_authority_id,
    NULL::bytea AS checks_authority_identity_digest,
    NULL::bigint AS checks_authority_app_configuration_revision,
    NULL::bigint AS checks_authority_policy_revision,
    registry.repository_contents_authority_id,
    registry.repository_contents_authority_identity_digest,
    registry.repository_contents_authority_app_configuration_revision,
    registry.repository_contents_authority_policy_revision
   FROM ((github_schedule_workflow_run_evidence schedule_run
     JOIN github_schedule_registry_revisions registry ON (((registry.tenant_id = schedule_run.tenant_id) AND (registry.repository_id = schedule_run.repository_id) AND (registry.provider_connection_id = schedule_run.provider_connection_id) AND (registry.registry_id = schedule_run.registry_id) AND (registry.manifest_revision = schedule_run.provider_manifest_revision) AND (registry.manifest_digest = schedule_run.provider_manifest_digest) AND (registry.default_branch_ref = schedule_run.git_ref) AND (registry.source_revision = schedule_run.source_revision))))
     JOIN github_provider_manifest_revisions manifest ON (((manifest.tenant_id = schedule_run.tenant_id) AND (manifest.repository_id = schedule_run.repository_id) AND (manifest.provider_connection_id = schedule_run.provider_connection_id) AND (manifest.manifest_revision = schedule_run.provider_manifest_revision) AND (manifest.manifest_digest = schedule_run.provider_manifest_digest))));

CREATE TABLE logical_workflow_runs (
    run_id uuid NOT NULL,
    root_invocation_id uuid NOT NULL,
    orchestration_schema smallint DEFAULT 1 NOT NULL,
    admission_digest bytea NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    admitted_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    admission_graph_sealed_at_ms bigint,
    base_context_digest bytea,
    base_context_object_key text COLLATE pg_catalog."C",
    base_context_size_bytes bigint,
    base_context_media_type text COLLATE pg_catalog."C",
    base_context_schema smallint,
    runner_requirements_schema smallint NOT NULL,
    CONSTRAINT logical_workflow_runs_admission_graph_seal_time CHECK (((admission_graph_sealed_at_ms IS NULL) OR (admission_graph_sealed_at_ms >= admitted_at_ms))),
    CONSTRAINT logical_workflow_runs_base_context CHECK ((((base_context_digest IS NULL) AND (base_context_object_key IS NULL) AND (base_context_size_bytes IS NULL) AND (base_context_media_type IS NULL) AND (base_context_schema IS NULL)) OR ((base_context_digest IS NOT NULL) AND (base_context_object_key IS NOT NULL) AND (base_context_size_bytes IS NOT NULL) AND (base_context_media_type IS NOT NULL) AND (base_context_schema IS NOT NULL) AND (octet_length(base_context_digest) = 32) AND ((octet_length(base_context_object_key) >= 1) AND (octet_length(base_context_object_key) <= 1024)) AND (base_context_object_key !~ '[[:cntrl:]]'::text) AND ("left"(base_context_object_key, 1) <> '/'::text) AND (base_context_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((base_context_size_bytes >= 1) AND (base_context_size_bytes <= 16777216)) AND (base_context_media_type = 'application/vnd.automata.job-runtime-context.protobuf'::text) AND (base_context_schema = 1)))),
    CONSTRAINT logical_workflow_runs_digest_sha256 CHECK ((octet_length(admission_digest) = 32)),
    CONSTRAINT logical_workflow_runs_revision_positive CHECK ((revision > 0)),
    CONSTRAINT logical_workflow_runs_root_non_nil CHECK ((root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_runs_run_non_nil CHECK ((run_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_runs_runner_requirements_schema CHECK ((runner_requirements_schema = 1)),
    CONSTRAINT logical_workflow_runs_schema_exact CHECK ((orchestration_schema = 1)),
    CONSTRAINT logical_workflow_runs_state CHECK ((state = ANY (ARRAY['pending'::text, 'active'::text, 'completed'::text, 'cancelled'::text, 'failed'::text]))),
    CONSTRAINT logical_workflow_runs_time_monotonic CHECK (((admitted_at_ms >= 0) AND (updated_at_ms >= admitted_at_ms)))
);

COMMENT ON COLUMN logical_workflow_runs.runner_requirements_schema IS 'Immutable runner-requirements schema authenticated by this admitted plan.';

CREATE TABLE workflow_rerun_attempts (
    run_id uuid NOT NULL,
    root_run_id uuid NOT NULL,
    source_run_id uuid,
    attempt integer NOT NULL,
    source_admission_digest bytea NOT NULL,
    source_plan_digest bytea NOT NULL,
    source_event_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT workflow_rerun_attempts_digest_shape CHECK (((octet_length(source_admission_digest) = 32) AND (octet_length(source_plan_digest) = 32) AND (octet_length(source_event_digest) = 32))),
    CONSTRAINT workflow_rerun_attempts_ids_non_nil CHECK (((run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (root_run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((source_run_id IS NULL) OR (source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT workflow_rerun_attempts_root_shape CHECK ((((source_run_id IS NULL) AND (run_id = root_run_id) AND (attempt = 1)) OR ((source_run_id IS NOT NULL) AND (run_id <> root_run_id) AND ((attempt >= 2) AND (attempt <= 51))))),
    CONSTRAINT workflow_rerun_attempts_time CHECK ((created_at_ms >= 0))
);

CREATE TABLE workflow_rerun_check_evidence (
    run_id uuid NOT NULL,
    source_run_id uuid NOT NULL,
    tenant_id text NOT NULL,
    operation_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    provider_manifest_revision bigint CONSTRAINT workflow_rerun_check_eviden_provider_manifest_revision_not_null NOT NULL,
    provider_manifest_digest bytea NOT NULL,
    source_github_check_subject_id uuid CONSTRAINT workflow_rerun_check_eviden_source_github_check_subjec_not_null NOT NULL,
    github_check_subject_id uuid NOT NULL,
    github_check_head_sha bytea NOT NULL,
    checks_authority_id uuid NOT NULL,
    checks_authority_identity_digest bytea CONSTRAINT workflow_rerun_check_eviden_checks_authority_identity__not_null NOT NULL,
    checks_authority_app_configuration_revision bigint CONSTRAINT workflow_rerun_check_eviden_checks_authority_app_confi_not_null NOT NULL,
    checks_authority_policy_revision bigint CONSTRAINT workflow_rerun_check_eviden_checks_authority_policy_re_not_null NOT NULL,
    repository_contents_authority_id uuid NOT NULL,
    repository_contents_authority_identity_digest bytea NOT NULL,
    repository_contents_authority_app_configuration_revision bigint NOT NULL,
    repository_contents_authority_policy_revision bigint NOT NULL,
    recorded_at_ms bigint NOT NULL,
    CONSTRAINT workflow_rerun_check_evidence_ids_non_nil CHECK (((run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (source_github_check_subject_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (github_check_subject_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (checks_authority_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_contents_authority_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT workflow_rerun_check_evidence_shape CHECK (((provider_manifest_revision > 0) AND (octet_length(provider_manifest_digest) = 32) AND (octet_length(github_check_head_sha) = 20) AND (github_check_head_sha <> decode(repeat('00'::text, 20), 'hex'::text)) AND (octet_length(checks_authority_identity_digest) = 32) AND (checks_authority_app_configuration_revision > 0) AND (checks_authority_policy_revision > 0) AND (octet_length(repository_contents_authority_identity_digest) = 32) AND (repository_contents_authority_app_configuration_revision > 0) AND (repository_contents_authority_policy_revision > 0) AND (recorded_at_ms >= 0)))
);

CREATE TABLE workflow_rerun_requests (
    tenant_id text NOT NULL,
    operation_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    repository_id uuid NOT NULL,
    source_run_id uuid NOT NULL,
    selection_kind text NOT NULL,
    selected_source_job_id uuid,
    actor_principal_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    authorization_revision bigint NOT NULL,
    rerun_run_id uuid,
    committed_at_ms bigint,
    CONSTRAINT workflow_rerun_requests_completion_shape CHECK ((((rerun_run_id IS NULL) AND (committed_at_ms IS NULL)) OR ((rerun_run_id IS NOT NULL) AND (committed_at_ms IS NOT NULL) AND (committed_at_ms >= 0)))),
    CONSTRAINT workflow_rerun_requests_digest_shape CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT workflow_rerun_requests_ids_non_nil CHECK (((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (actor_principal_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (actor_session_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((rerun_run_id IS NULL) OR (rerun_run_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT workflow_rerun_requests_revision_positive CHECK ((authorization_revision > 0)),
    CONSTRAINT workflow_rerun_requests_selection_shape CHECK ((((selection_kind = ANY (ARRAY['entire_workflow'::text, 'failed_jobs_and_dependents'::text])) AND (selected_source_job_id IS NULL)) OR ((selection_kind = 'job_and_dependents'::text) AND (selected_source_job_id IS NOT NULL))))
);

CREATE TABLE workflow_runs (
    id uuid NOT NULL,
    repository_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    run_number bigint NOT NULL,
    run_attempt integer DEFAULT 1 NOT NULL,
    event_name text NOT NULL,
    event_object_key text NOT NULL,
    head_sha bytea NOT NULL,
    status text NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    concurrency_group_key text,
    admission_epoch integer DEFAULT 1 NOT NULL,
    event_digest bytea NOT NULL,
    event_size_bytes bigint NOT NULL,
    event_media_type text NOT NULL,
    plan_digest bytea NOT NULL,
    plan_object_key text NOT NULL,
    plan_size_bytes bigint NOT NULL,
    plan_media_type text NOT NULL,
    plan_schema integer NOT NULL,
    workflow_name text NOT NULL,
    git_ref text,
    actor text,
    display_title text,
    commit_subject text,
    publication_policy_revision bigint DEFAULT 1 NOT NULL,
    requested_dashboard_visibility text DEFAULT 'private'::text NOT NULL,
    effective_dashboard_visibility text DEFAULT 'private'::text NOT NULL,
    requested_log_visibility text DEFAULT 'private'::text NOT NULL,
    requested_artifact_visibility text DEFAULT 'private'::text NOT NULL,
    publication_safety_reason text DEFAULT 'repository_policy'::text NOT NULL,
    publication_safety_schema integer DEFAULT 1 NOT NULL,
    run_id_alias bigint NOT NULL,
    concurrency_queue_policy text,
    runner_requirements_schema smallint NOT NULL,
    public_run_id_alias bigint NOT NULL,
    triggering_actor text,
    concurrency_cancel_in_progress boolean,
    CONSTRAINT workflow_runs_actor_shape CHECK (((actor IS NULL) OR (((octet_length(actor) >= 1) AND (octet_length(actor) <= 1024)) AND (actor !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT workflow_runs_admission_epoch CHECK ((admission_epoch = 1)),
    CONSTRAINT workflow_runs_attempt_positive CHECK ((run_attempt > 0)),
    CONSTRAINT workflow_runs_commit_subject_shape CHECK (((commit_subject IS NULL) OR (((octet_length(commit_subject) >= 1) AND (octet_length(commit_subject) <= 1024)) AND (commit_subject !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT workflow_runs_concurrency_cancel_shape CHECK (((concurrency_group_key IS NOT NULL) OR (concurrency_cancel_in_progress IS NULL))),
    CONSTRAINT workflow_runs_concurrency_key_shape CHECK (((concurrency_group_key IS NULL) OR (((octet_length(concurrency_group_key) >= 1) AND (octet_length(concurrency_group_key) <= 255)) AND (concurrency_group_key !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT workflow_runs_concurrency_queue_policy_shape CHECK ((((concurrency_group_key IS NULL) AND (concurrency_queue_policy IS NULL)) OR ((concurrency_group_key IS NOT NULL) AND (concurrency_queue_policy = ANY (ARRAY['single'::text, 'max'::text]))))),
    CONSTRAINT workflow_runs_current_event_metadata CHECK (((admission_epoch = 1) AND (octet_length(event_digest) = 32) AND ((event_size_bytes >= 1) AND (event_size_bytes <= 26214400)) AND ((octet_length(event_media_type) >= 3) AND (octet_length(event_media_type) <= 128)) AND (event_media_type ~~ '%/%'::text) AND (event_media_type !~ '[[:space:][:cntrl:];]'::text) AND (octet_length(plan_digest) = 32) AND ((octet_length(plan_object_key) >= 1) AND (octet_length(plan_object_key) <= 1024)) AND (plan_object_key !~ '[[:cntrl:]]'::text) AND ((plan_size_bytes >= 1) AND (plan_size_bytes <= 16777216)) AND ((octet_length(plan_media_type) >= 3) AND (octet_length(plan_media_type) <= 128)) AND (plan_media_type ~~ '%/%'::text) AND (plan_media_type !~ '[[:space:][:cntrl:];]'::text) AND (plan_schema = 1))),
    CONSTRAINT workflow_runs_dashboard_visibility_cap CHECK (((effective_dashboard_visibility = 'private'::text) OR ((effective_dashboard_visibility = 'authenticated'::text) AND (requested_dashboard_visibility = ANY (ARRAY['authenticated'::text, 'public'::text]))) OR ((effective_dashboard_visibility = 'public'::text) AND (requested_dashboard_visibility = 'public'::text)))),
    CONSTRAINT workflow_runs_display_title_shape CHECK (((display_title IS NULL) OR (((octet_length(display_title) >= 1) AND (octet_length(display_title) <= 1024)) AND (display_title !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT workflow_runs_effective_dashboard_visibility CHECK ((effective_dashboard_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text]))),
    CONSTRAINT workflow_runs_git_ref_shape CHECK (((git_ref IS NULL) OR (((octet_length(git_ref) >= 6) AND (octet_length(git_ref) <= 1024)) AND (git_ref ~~ 'refs/%'::text) AND (git_ref !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT workflow_runs_id_alias_exact_positive CHECK (((run_id_alias >= 1) AND (run_id_alias <= '9007199254740991'::bigint))),
    CONSTRAINT workflow_runs_number_positive CHECK ((run_number > 0)),
    CONSTRAINT workflow_runs_public_id_alias_positive CHECK (((public_run_id_alias IS NULL) OR ((public_run_id_alias >= 1) AND (public_run_id_alias <= '9007199254740991'::bigint)))),
    CONSTRAINT workflow_runs_publication_policy_revision_positive CHECK ((publication_policy_revision > 0)),
    CONSTRAINT workflow_runs_publication_safety_reason_code CHECK ((publication_safety_reason = ANY (ARRAY['repository_policy'::text, 'secret_exposure'::text]))),
    CONSTRAINT workflow_runs_publication_safety_schema CHECK ((publication_safety_schema = 1)),
    CONSTRAINT workflow_runs_requested_visibility CHECK (((requested_dashboard_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text])) AND (requested_log_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text])) AND (requested_artifact_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text])))),
    CONSTRAINT workflow_runs_runner_requirements_schema CHECK ((runner_requirements_schema = 1)),
    CONSTRAINT workflow_runs_sha CHECK ((octet_length(head_sha) = ANY (ARRAY[20, 32]))),
    CONSTRAINT workflow_runs_status CHECK ((status = ANY (ARRAY['queued'::text, 'in_progress'::text, 'completed'::text, 'cancelled'::text]))),
    CONSTRAINT workflow_runs_triggering_actor_shape CHECK (((triggering_actor IS NULL) OR (((octet_length(triggering_actor) >= 1) AND (octet_length(triggering_actor) <= 1024)) AND (triggering_actor !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT workflow_runs_workflow_name_shape CHECK ((((octet_length(workflow_name) >= 1) AND (octet_length(workflow_name) <= 1024)) AND (workflow_name !~ '[[:cntrl:]]'::text)))
);

CREATE VIEW github_workflow_run_manifest_origins AS
 SELECT github_workflow_run_base_manifest_origins.tenant_id,
    github_workflow_run_base_manifest_origins.repository_id,
    github_workflow_run_base_manifest_origins.workflow_id,
    github_workflow_run_base_manifest_origins.snapshot_id,
    github_workflow_run_base_manifest_origins.run_id,
    github_workflow_run_base_manifest_origins.root_invocation_id,
    github_workflow_run_base_manifest_origins.origin_kind,
    github_workflow_run_base_manifest_origins.origin_id,
    github_workflow_run_base_manifest_origins.admission_idempotency_kind,
    github_workflow_run_base_manifest_origins.admission_idempotency_key,
    github_workflow_run_base_manifest_origins.github_check_subject_id,
    github_workflow_run_base_manifest_origins.github_check_head_sha,
    github_workflow_run_base_manifest_origins.workflow_path,
    github_workflow_run_base_manifest_origins.source_digest,
    github_workflow_run_base_manifest_origins.event_name,
    github_workflow_run_base_manifest_origins.event_digest,
    github_workflow_run_base_manifest_origins.git_ref,
    github_workflow_run_base_manifest_origins.workflow_plan_schema,
    github_workflow_run_base_manifest_origins.plan_digest,
    github_workflow_run_base_manifest_origins.logical_admission_digest,
    github_workflow_run_base_manifest_origins.admitted_at_ms,
    github_workflow_run_base_manifest_origins.subject_evidence_sha256,
    github_workflow_run_base_manifest_origins.provider_connection_id,
    github_workflow_run_base_manifest_origins.provider_installation_id,
    github_workflow_run_base_manifest_origins.github_repository_id,
    github_workflow_run_base_manifest_origins.github_repository_owner_id,
    github_workflow_run_base_manifest_origins.github_repository_name,
    github_workflow_run_base_manifest_origins.repository_visibility,
    github_workflow_run_base_manifest_origins.provider_manifest_revision,
    github_workflow_run_base_manifest_origins.provider_manifest_digest,
    github_workflow_run_base_manifest_origins.authenticated_webhook_verifier_fingerprint_sha256,
    github_workflow_run_base_manifest_origins.authenticated_webhook_verifier_revision,
    github_workflow_run_base_manifest_origins.checks_authority_id,
    github_workflow_run_base_manifest_origins.checks_authority_identity_digest,
    github_workflow_run_base_manifest_origins.checks_authority_app_configuration_revision,
    github_workflow_run_base_manifest_origins.checks_authority_policy_revision,
    github_workflow_run_base_manifest_origins.repository_contents_authority_id,
    github_workflow_run_base_manifest_origins.repository_contents_authority_identity_digest,
    github_workflow_run_base_manifest_origins.repository_contents_authority_app_configuration_revision,
    github_workflow_run_base_manifest_origins.repository_contents_authority_policy_revision
   FROM github_workflow_run_base_manifest_origins
UNION ALL
 SELECT origin.tenant_id,
    origin.repository_id,
    rerun.workflow_id,
    rerun.snapshot_id,
    attempt.run_id,
    marker.root_invocation_id,
    'workflow_rerun'::text AS origin_kind,
    request.operation_id AS origin_id,
    'operation'::text AS admission_idempotency_kind,
    ('workflow-rerun:'::text || (request.operation_id)::text) AS admission_idempotency_key,
    run_evidence.github_check_subject_id,
    run_evidence.github_check_head_sha,
    run_evidence.workflow_path,
    run_evidence.source_digest,
    run_evidence.event_name,
    run_evidence.event_digest,
    run_evidence.git_ref,
    run_evidence.workflow_plan_schema,
    run_evidence.plan_digest,
    run_evidence.logical_admission_digest,
    run_evidence.admitted_at_ms,
    run_evidence.subject_evidence_sha256,
    check_evidence.provider_connection_id,
    origin.provider_installation_id,
    origin.github_repository_id,
    origin.github_repository_owner_id,
    origin.github_repository_name,
    origin.repository_visibility,
    check_evidence.provider_manifest_revision,
    check_evidence.provider_manifest_digest,
    origin.authenticated_webhook_verifier_fingerprint_sha256,
    origin.authenticated_webhook_verifier_revision,
    check_evidence.checks_authority_id,
    check_evidence.checks_authority_identity_digest,
    check_evidence.checks_authority_app_configuration_revision,
    check_evidence.checks_authority_policy_revision,
    check_evidence.repository_contents_authority_id,
    check_evidence.repository_contents_authority_identity_digest,
    check_evidence.repository_contents_authority_app_configuration_revision,
    check_evidence.repository_contents_authority_policy_revision
   FROM ((((((workflow_rerun_attempts attempt
     JOIN workflow_rerun_check_evidence check_evidence ON (((check_evidence.run_id = attempt.run_id) AND (check_evidence.source_run_id = attempt.source_run_id))))
     JOIN workflow_rerun_requests request ON (((request.tenant_id = check_evidence.tenant_id) AND (request.operation_id = check_evidence.operation_id) AND (request.rerun_run_id = attempt.run_id) AND (request.committed_at_ms = attempt.created_at_ms))))
     JOIN workflow_runs rerun ON ((rerun.id = attempt.run_id)))
     JOIN logical_workflow_runs marker ON ((marker.run_id = attempt.run_id)))
     JOIN github_workflow_rerun_subject_evidence run_evidence ON (((run_evidence.tenant_id = check_evidence.tenant_id) AND (run_evidence.operation_id = check_evidence.operation_id) AND (run_evidence.run_id = check_evidence.run_id) AND (run_evidence.source_run_id = check_evidence.source_run_id) AND (run_evidence.github_check_subject_id = check_evidence.github_check_subject_id) AND (run_evidence.github_check_head_sha = check_evidence.github_check_head_sha) AND (run_evidence.admitted_at_ms = check_evidence.recorded_at_ms))))
     JOIN github_workflow_run_base_manifest_origins origin ON (((origin.run_id = attempt.root_run_id) AND (origin.tenant_id = check_evidence.tenant_id) AND (origin.repository_id = check_evidence.repository_id) AND (origin.provider_connection_id = check_evidence.provider_connection_id) AND (origin.provider_manifest_revision = check_evidence.provider_manifest_revision) AND (origin.provider_manifest_digest = check_evidence.provider_manifest_digest))))
  WHERE (attempt.source_run_id IS NOT NULL);
