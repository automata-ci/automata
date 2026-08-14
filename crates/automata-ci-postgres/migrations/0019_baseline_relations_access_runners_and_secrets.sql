CREATE TABLE rbac_permissions (
    name text NOT NULL,
    description text NOT NULL,
    critical boolean DEFAULT false NOT NULL,
    created_at_ms bigint DEFAULT 0 NOT NULL,
    CONSTRAINT rbac_permissions_created_nonnegative CHECK ((created_at_ms >= 0)),
    CONSTRAINT rbac_permissions_description_shape CHECK ((((octet_length(description) >= 1) AND (octet_length(description) <= 1024)) AND (description !~ '[[:cntrl:]]'::text))),
    CONSTRAINT rbac_permissions_name_shape CHECK ((((octet_length(name) >= 1) AND (octet_length(name) <= 128)) AND (name ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)))
);

CREATE TABLE rbac_role_bindings (
    tenant_id text NOT NULL,
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    role_id uuid NOT NULL,
    scope_kind text NOT NULL,
    repository_id uuid,
    runner_group_id uuid,
    assignment_source text DEFAULT 'manual'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_by_principal_id uuid,
    revoked_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    valid_until_ms bigint,
    revoked_at_ms bigint,
    revocation_reason text,
    revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT rbac_role_bindings_lifetime CHECK (((valid_until_ms IS NULL) OR (valid_until_ms > created_at_ms))),
    CONSTRAINT rbac_role_bindings_revision_positive CHECK ((revision > 0)),
    CONSTRAINT rbac_role_bindings_revocation_shape CHECK (((((status = 'active'::text) AND (revoked_by_principal_id IS NULL) AND (revoked_at_ms IS NULL) AND (revocation_reason IS NULL)) OR ((status = 'revoked'::text) AND (revoked_at_ms >= created_at_ms) AND ((octet_length(revocation_reason) >= 1) AND (octet_length(revocation_reason) <= 1024)) AND (revocation_reason !~ '[[:cntrl:]]'::text))) IS TRUE)),
    CONSTRAINT rbac_role_bindings_scope_kind CHECK ((scope_kind = ANY (ARRAY['tenant'::text, 'repository'::text, 'runner_group'::text]))),
    CONSTRAINT rbac_role_bindings_scope_shape CHECK (((((scope_kind = 'tenant'::text) AND (repository_id IS NULL) AND (runner_group_id IS NULL)) OR ((scope_kind = 'repository'::text) AND (repository_id IS NOT NULL) AND (runner_group_id IS NULL)) OR ((scope_kind = 'runner_group'::text) AND (repository_id IS NULL) AND (runner_group_id IS NOT NULL))) IS TRUE)),
    CONSTRAINT rbac_role_bindings_source CHECK ((assignment_source = ANY (ARRAY['manual'::text, 'bootstrap'::text, 'recovery'::text]))),
    CONSTRAINT rbac_role_bindings_status CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text])))
);

CREATE TABLE rbac_role_permissions (
    tenant_id text NOT NULL,
    role_id uuid NOT NULL,
    permission_name text NOT NULL,
    granted_by_principal_id uuid,
    granted_at_ms bigint NOT NULL
);

CREATE TABLE rbac_roles (
    tenant_id text NOT NULL,
    id uuid NOT NULL,
    name text NOT NULL,
    display_name text NOT NULL,
    role_kind text DEFAULT 'custom'::text NOT NULL,
    immutable boolean DEFAULT false NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT rbac_roles_display_name_shape CHECK ((((octet_length(display_name) >= 1) AND (octet_length(display_name) <= 255)) AND (display_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT rbac_roles_immutability_shape CHECK ((((role_kind = 'built_in'::text) AND immutable) OR (role_kind = 'custom'::text))),
    CONSTRAINT rbac_roles_kind CHECK ((role_kind = ANY (ARRAY['built_in'::text, 'custom'::text]))),
    CONSTRAINT rbac_roles_name_shape CHECK ((((octet_length(name) >= 1) AND (octet_length(name) <= 128)) AND (name ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))),
    CONSTRAINT rbac_roles_revision_positive CHECK ((revision > 0)),
    CONSTRAINT rbac_roles_time_monotonic CHECK ((updated_at_ms >= created_at_ms))
);

CREATE TABLE repositories (
    id uuid NOT NULL,
    tenant_id text NOT NULL,
    scm_provider text NOT NULL,
    provider_repository_id text NOT NULL,
    owner text NOT NULL,
    name text NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT repositories_name_nonempty CHECK ((length(name) > 0)),
    CONSTRAINT repositories_owner_nonempty CHECK ((length(owner) > 0))
);

CREATE TABLE repository_environment_reviewers (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    environment_revision bigint NOT NULL,
    principal_id uuid NOT NULL,
    principal_authorization_revision bigint CONSTRAINT repository_environment_revi_principal_authorization_re_not_null NOT NULL,
    granted_by_principal_id uuid,
    grantor_authorization_revision bigint,
    granted_at_ms bigint NOT NULL,
    CONSTRAINT repository_environment_reviewers_revision CHECK (((environment_revision > 0) AND (principal_authorization_revision > 0) AND (granted_by_principal_id IS NOT NULL) AND (grantor_authorization_revision > 0))),
    CONSTRAINT repository_environment_reviewers_time CHECK ((granted_at_ms >= 0))
);

CREATE TABLE repository_environments (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    id uuid NOT NULL,
    name text NOT NULL,
    normalized_name text NOT NULL,
    protection_mode text DEFAULT 'unprotected'::text NOT NULL,
    required_approvals smallint DEFAULT 0 NOT NULL,
    prevent_self_review boolean DEFAULT true NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT repository_environments_name_shape CHECK ((((octet_length(name) >= 1) AND (octet_length(name) <= 255)) AND (name !~ '[[:cntrl:]]'::text) AND ((octet_length(normalized_name) >= 1) AND (octet_length(normalized_name) <= 255)) AND (normalized_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT repository_environments_protection_mode CHECK ((protection_mode = ANY (ARRAY['unprotected'::text, 'required_approvals'::text]))),
    CONSTRAINT repository_environments_protection_shape CHECK ((((protection_mode = 'unprotected'::text) AND (required_approvals = 0)) OR ((protection_mode = 'required_approvals'::text) AND ((required_approvals >= 1) AND (required_approvals <= 25))))),
    CONSTRAINT repository_environments_revision_positive CHECK ((revision > 0)),
    CONSTRAINT repository_environments_status CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT repository_environments_time_monotonic CHECK ((updated_at_ms >= created_at_ms))
);

CREATE TABLE repository_publication_policies (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    dashboard_audience text DEFAULT 'private'::text NOT NULL,
    log_audience text DEFAULT 'private'::text NOT NULL,
    artifact_audience text DEFAULT 'private'::text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT repository_publication_policies_artifact_audience CHECK ((artifact_audience = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text]))),
    CONSTRAINT repository_publication_policies_dashboard_audience CHECK ((dashboard_audience = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text]))),
    CONSTRAINT repository_publication_policies_log_audience CHECK ((log_audience = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text]))),
    CONSTRAINT repository_publication_policies_revision_positive CHECK ((revision > 0)),
    CONSTRAINT repository_publication_policies_time_monotonic CHECK ((updated_at_ms >= created_at_ms))
);

CREATE TABLE runner_command_outbox (
    runner_session_id uuid NOT NULL,
    command_sequence bigint NOT NULL,
    operation_id uuid NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_epoch bigint NOT NULL,
    runner_generation bigint NOT NULL,
    command_kind text NOT NULL,
    command_schema integer NOT NULL,
    command_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    tenant_id text NOT NULL,
    command_plaintext_size_bytes bigint NOT NULL,
    envelope_schema integer,
    wrapping_key_id text,
    wrapped_data_key bytea,
    nonce bytea,
    ciphertext bytea,
    payload_tombstone_reason text,
    payload_tombstoned_at_ms bigint,
    CONSTRAINT runner_command_outbox_ciphertext_size CHECK ((((octet_length(ciphertext))::numeric = ((command_plaintext_size_bytes)::numeric + (16)::numeric)) AND (octet_length(ciphertext) <= 16777232))),
    CONSTRAINT runner_command_outbox_envelope_schema_v1 CHECK ((envelope_schema = 1)),
    CONSTRAINT runner_command_outbox_kind_shape CHECK ((((octet_length(command_kind) >= 1) AND (octet_length(command_kind) <= 128)) AND (command_kind ~ '^[a-z0-9][a-z0-9._/-]*$'::text))),
    CONSTRAINT runner_command_outbox_nonce_size CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT runner_command_outbox_payload_lifecycle CHECK ((((payload_tombstone_reason IS NULL) AND (payload_tombstoned_at_ms IS NULL) AND (envelope_schema IS NOT NULL) AND (wrapping_key_id IS NOT NULL) AND (wrapped_data_key IS NOT NULL) AND (nonce IS NOT NULL) AND (ciphertext IS NOT NULL)) OR ((payload_tombstone_reason = ANY (ARRAY['acknowledged'::text, 'session_closed'::text, 'session_superseded'::text])) AND (payload_tombstoned_at_ms IS NOT NULL) AND (payload_tombstoned_at_ms >= created_at_ms) AND (envelope_schema IS NULL) AND (wrapping_key_id IS NULL) AND (wrapped_data_key IS NULL) AND (nonce IS NULL) AND (ciphertext IS NULL)))),
    CONSTRAINT runner_command_outbox_plaintext_size_range CHECK (((command_plaintext_size_bytes >= 1) AND (command_plaintext_size_bytes <= 16777216))),
    CONSTRAINT runner_command_outbox_schema_range CHECK (((command_schema >= 1) AND (command_schema <= 65535))),
    CONSTRAINT runner_command_outbox_sequence_positive CHECK ((command_sequence > 0)),
    CONSTRAINT runner_command_outbox_sha256 CHECK ((octet_length(command_digest) = 32)),
    CONSTRAINT runner_command_outbox_wrapped_data_key_size CHECK (((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 65536))),
    CONSTRAINT runner_command_outbox_wrapping_key_id_canonical CHECK ((((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 64)) AND (wrapping_key_id ~ '^[a-z0-9][a-z0-9._-]*$'::text) AND ("right"(wrapping_key_id, 1) ~ '^[a-z0-9]$'::text)))
);

CREATE TABLE runner_groups (
    id uuid NOT NULL,
    tenant_id text NOT NULL,
    name text NOT NULL,
    normalized_name text NOT NULL,
    routing_policy jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT runner_groups_name_nonempty CHECK ((length(name) > 0))
);

CREATE TABLE runner_lease_offer_publications (
    runner_session_id uuid NOT NULL,
    request_operation_id uuid NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_epoch bigint NOT NULL,
    runner_generation bigint NOT NULL,
    operation_kind text NOT NULL,
    request_digest bytea NOT NULL,
    protocol_version integer NOT NULL,
    runner_slot integer NOT NULL,
    attempt_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    lease_issued_at_ms bigint NOT NULL,
    lease_expires_at_ms bigint NOT NULL,
    job_id uuid NOT NULL,
    run_id uuid NOT NULL,
    job_ir_schema integer NOT NULL,
    job_ir_size_bytes bigint NOT NULL,
    job_ir_digest bytea NOT NULL,
    job_ir_object_key text NOT NULL,
    command_sequence bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    offer_valid_until_ms bigint NOT NULL,
    delivery_revoked_at_ms bigint,
    delivery_revocation_reason text,
    CONSTRAINT runner_lease_offer_publications_authority_horizon CHECK (((created_at_ms >= lease_issued_at_ms) AND (offer_valid_until_ms > created_at_ms) AND (offer_valid_until_ms <= lease_expires_at_ms))),
    CONSTRAINT runner_lease_offer_publications_command_sequence_positive CHECK ((command_sequence > 0)),
    CONSTRAINT runner_lease_offer_publications_delivery_revocation CHECK ((((delivery_revoked_at_ms IS NULL) AND (delivery_revocation_reason IS NULL)) OR ((delivery_revoked_at_ms >= created_at_ms) AND (delivery_revocation_reason = ANY (ARRAY['attempt_superseded'::text, 'authority_expired'::text])) AND ((delivery_revocation_reason <> 'authority_expired'::text) OR (delivery_revoked_at_ms >= offer_valid_until_ms))))),
    CONSTRAINT runner_lease_offer_publications_fence_positive CHECK ((fencing_token > 0)),
    CONSTRAINT runner_lease_offer_publications_job_ir_shape CHECK (((job_ir_schema = 1) AND ((job_ir_size_bytes >= 1) AND (job_ir_size_bytes <= 16777216)) AND (octet_length(job_ir_digest) = 32) AND ((octet_length(job_ir_object_key) >= 1) AND (octet_length(job_ir_object_key) <= 1024)) AND (job_ir_object_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT runner_lease_offer_publications_kind_shape CHECK ((((octet_length(operation_kind) >= 1) AND (octet_length(operation_kind) <= 128)) AND (operation_kind ~ '^[a-z0-9][a-z0-9._/-]*$'::text))),
    CONSTRAINT runner_lease_offer_publications_lease_interval CHECK ((lease_expires_at_ms > lease_issued_at_ms)),
    CONSTRAINT runner_lease_offer_publications_protocol_range CHECK (((protocol_version >= 1) AND (protocol_version <= 65535))),
    CONSTRAINT runner_lease_offer_publications_request_sha256 CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT runner_lease_offer_publications_slot_range CHECK (((runner_slot >= 1) AND (runner_slot <= 65535)))
);

CREATE TABLE runner_lease_request_heads (
    runner_session_id uuid NOT NULL,
    runner_slot integer NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_epoch bigint NOT NULL,
    runner_generation bigint NOT NULL,
    operation_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    acknowledges_operation_id uuid,
    CONSTRAINT runner_lease_request_heads_predecessor_distinct CHECK (((acknowledges_operation_id IS NULL) OR (acknowledges_operation_id <> operation_id))),
    CONSTRAINT runner_lease_request_heads_request_sha256 CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT runner_lease_request_heads_slot_range CHECK (((runner_slot >= 1) AND (runner_slot <= 65535)))
);

CREATE TABLE runner_machine_certificates (
    leaf_sha256 bytea NOT NULL,
    runner_id uuid NOT NULL,
    expires_at_seconds bigint NOT NULL,
    revoked_at_seconds bigint,
    CONSTRAINT runner_machine_certificates_expiration_positive CHECK ((expires_at_seconds > 0)),
    CONSTRAINT runner_machine_certificates_leaf_sha256 CHECK ((octet_length(leaf_sha256) = 32)),
    CONSTRAINT runner_machine_certificates_revocation_monotonic CHECK (((revoked_at_seconds IS NULL) OR ((revoked_at_seconds > 0) AND (revoked_at_seconds <= expires_at_seconds))))
);

CREATE TABLE runner_enrollment_tokens (
    id uuid NOT NULL,
    tenant_id text NOT NULL,
    runner_group_id uuid NOT NULL,
    token_sha256 bytea NOT NULL,
    issued_by_principal_id uuid NOT NULL,
    issued_by_session_id uuid NOT NULL,
    issued_authorization_revision bigint NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    consumed_at_ms bigint,
    consumed_runner_id uuid,
    redeem_operation_id uuid,
    redeem_request_sha256 bytea,
    redeem_response bytea,
    redeem_certificate_expires_at_seconds bigint,
    CONSTRAINT runner_enrollment_tokens_digest CHECK ((octet_length(token_sha256) = 32)),
    CONSTRAINT runner_enrollment_tokens_ids_non_nil CHECK (((id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (runner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (issued_by_principal_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (issued_by_session_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((consumed_runner_id IS NULL) OR (consumed_runner_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((redeem_operation_id IS NULL) OR (redeem_operation_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT runner_enrollment_tokens_lifetime CHECK (((issued_at_ms >= 0) AND ((expires_at_ms - issued_at_ms) >= 60000) AND ((expires_at_ms - issued_at_ms) <= 3600000))),
    CONSTRAINT runner_enrollment_tokens_revision_positive CHECK ((issued_authorization_revision > 0)),
    CONSTRAINT runner_enrollment_tokens_consumption_shape CHECK (((((consumed_at_ms IS NULL) AND (consumed_runner_id IS NULL) AND (redeem_operation_id IS NULL) AND (redeem_request_sha256 IS NULL) AND (redeem_response IS NULL) AND (redeem_certificate_expires_at_seconds IS NULL)) OR ((consumed_at_ms >= issued_at_ms) AND (consumed_at_ms < expires_at_ms) AND (consumed_runner_id IS NOT NULL) AND (redeem_operation_id IS NOT NULL) AND (octet_length(redeem_request_sha256) = 32) AND (octet_length(redeem_response) >= 1) AND (octet_length(redeem_response) <= 524288) AND ((redeem_certificate_expires_at_seconds - (consumed_at_ms / 1000)) >= 300))) IS TRUE))
);

CREATE TABLE runner_operation_receipts (
    runner_session_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_epoch bigint NOT NULL,
    runner_generation bigint NOT NULL,
    operation_kind text NOT NULL,
    request_digest bytea NOT NULL,
    selection_kind text NOT NULL,
    requested_attempt_id uuid,
    requested_lease_id uuid,
    runner_slot integer NOT NULL,
    scan_cursor_version bigint NOT NULL,
    committed_cursor_version bigint,
    observed_at_ms bigint NOT NULL,
    lease_expires_at_ms bigint,
    outcome text NOT NULL,
    claimed_fencing_token bigint,
    rejection_lifecycle text,
    occupied_attempt_id uuid,
    claimed_job_id uuid,
    claimed_run_id uuid,
    claimed_job_ir_schema integer,
    claimed_job_ir_size_bytes bigint,
    claimed_job_ir_digest bytea,
    claimed_job_ir_object_key text,
    completed_at_ms bigint,
    CONSTRAINT runner_operation_receipts_cursor_versions CHECK (((scan_cursor_version >= 0) AND ((committed_cursor_version IS NULL) OR (committed_cursor_version = (scan_cursor_version + 1))))),
    CONSTRAINT runner_operation_receipts_fence_positive CHECK (((claimed_fencing_token IS NULL) OR (claimed_fencing_token > 0))),
    CONSTRAINT runner_operation_receipts_job_ir_shape CHECK ((((outcome = 'claimed'::text) AND (claimed_job_id IS NOT NULL) AND (claimed_run_id IS NOT NULL) AND (claimed_job_ir_schema = 1) AND ((claimed_job_ir_size_bytes >= 1) AND (claimed_job_ir_size_bytes <= 16777216)) AND (octet_length(claimed_job_ir_digest) = 32) AND ((octet_length(claimed_job_ir_object_key) >= 1) AND (octet_length(claimed_job_ir_object_key) <= 1024)) AND (claimed_job_ir_object_key !~ '[[:cntrl:]]'::text)) OR ((outcome <> 'claimed'::text) AND (claimed_job_id IS NULL) AND (claimed_run_id IS NULL) AND (claimed_job_ir_schema IS NULL) AND (claimed_job_ir_size_bytes IS NULL) AND (claimed_job_ir_digest IS NULL) AND (claimed_job_ir_object_key IS NULL)))),
    CONSTRAINT runner_operation_receipts_kind_shape CHECK ((((octet_length(operation_kind) >= 1) AND (octet_length(operation_kind) <= 128)) AND (operation_kind !~ '[[:cntrl:]]'::text))),
    CONSTRAINT runner_operation_receipts_lease_interval CHECK (((lease_expires_at_ms IS NULL) OR (lease_expires_at_ms > observed_at_ms))),
    CONSTRAINT runner_operation_receipts_outcome CHECK ((outcome = ANY (ARRAY['pending'::text, 'claimed'::text, 'no_work'::text, 'attempt_not_found'::text, 'not_queued'::text, 'not_routable'::text, 'not_runnable'::text, 'slot_out_of_range'::text, 'slot_occupied'::text, 'scan_superseded'::text, 'authority_rejected'::text]))),
    CONSTRAINT runner_operation_receipts_rejection_lifecycle CHECK (((rejection_lifecycle IS NULL) OR (rejection_lifecycle = ANY (ARRAY['queued'::text, 'leased'::text, 'preparing'::text, 'running'::text, 'cancelling'::text, 'finalizing'::text, 'succeeded'::text, 'failed'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text, 'lost'::text])))),
    CONSTRAINT runner_operation_receipts_result_shape CHECK ((((outcome = 'pending'::text) AND (claimed_fencing_token IS NULL) AND (rejection_lifecycle IS NULL) AND (occupied_attempt_id IS NULL) AND (committed_cursor_version IS NULL) AND (completed_at_ms IS NULL)) OR ((outcome = 'no_work'::text) AND (claimed_fencing_token IS NULL) AND (rejection_lifecycle IS NULL) AND (occupied_attempt_id IS NULL) AND (committed_cursor_version IS NOT NULL) AND (completed_at_ms IS NOT NULL)) OR ((outcome = 'claimed'::text) AND (claimed_fencing_token IS NOT NULL) AND (rejection_lifecycle IS NULL) AND (occupied_attempt_id IS NULL) AND (committed_cursor_version IS NOT NULL) AND (completed_at_ms IS NOT NULL)) OR ((outcome = 'not_queued'::text) AND (claimed_fencing_token IS NULL) AND (rejection_lifecycle IS NOT NULL) AND (occupied_attempt_id IS NULL) AND (committed_cursor_version IS NOT NULL) AND (completed_at_ms IS NOT NULL)) OR ((outcome = 'slot_occupied'::text) AND (claimed_fencing_token IS NULL) AND (rejection_lifecycle IS NULL) AND (occupied_attempt_id IS NOT NULL) AND (committed_cursor_version IS NOT NULL) AND (completed_at_ms IS NOT NULL)) OR ((outcome = ANY (ARRAY['attempt_not_found'::text, 'not_routable'::text, 'not_runnable'::text, 'slot_out_of_range'::text])) AND (claimed_fencing_token IS NULL) AND (rejection_lifecycle IS NULL) AND (occupied_attempt_id IS NULL) AND (committed_cursor_version IS NOT NULL) AND (completed_at_ms IS NOT NULL)) OR ((outcome = ANY (ARRAY['scan_superseded'::text, 'authority_rejected'::text])) AND (claimed_fencing_token IS NULL) AND (rejection_lifecycle IS NULL) AND (occupied_attempt_id IS NULL) AND (committed_cursor_version IS NULL) AND (completed_at_ms IS NOT NULL)))),
    CONSTRAINT runner_operation_receipts_selection_kind CHECK ((selection_kind = ANY (ARRAY['claim'::text, 'no_work'::text]))),
    CONSTRAINT runner_operation_receipts_selection_shape CHECK ((((selection_kind = 'no_work'::text) AND (requested_attempt_id IS NULL) AND (requested_lease_id IS NULL) AND (lease_expires_at_ms IS NULL)) OR ((selection_kind = 'claim'::text) AND (requested_attempt_id IS NOT NULL) AND (requested_lease_id IS NOT NULL) AND (lease_expires_at_ms IS NOT NULL)))),
    CONSTRAINT runner_operation_receipts_sha256 CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT runner_operation_receipts_slot_range CHECK (((runner_slot >= 1) AND (runner_slot <= 65535)))
);

CREATE TABLE runner_queue_cursors (
    runner_id uuid NOT NULL,
    runner_slot integer NOT NULL,
    runner_generation bigint NOT NULL,
    routing_fingerprint bytea NOT NULL,
    cursor_version bigint NOT NULL,
    after_queued_at_ms bigint,
    after_attempt_id uuid,
    cycle_upper_queued_at_ms bigint,
    cycle_upper_attempt_id uuid,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT runner_queue_cursors_after_complete CHECK (((after_queued_at_ms IS NULL) = (after_attempt_id IS NULL))),
    CONSTRAINT runner_queue_cursors_after_within_cycle CHECK (((after_queued_at_ms IS NULL) OR (cycle_upper_queued_at_ms IS NULL) OR (ROW(after_queued_at_ms, after_attempt_id) <= ROW(cycle_upper_queued_at_ms, cycle_upper_attempt_id)))),
    CONSTRAINT runner_queue_cursors_generation_positive CHECK ((runner_generation > 0)),
    CONSTRAINT runner_queue_cursors_sha256 CHECK ((octet_length(routing_fingerprint) = 32)),
    CONSTRAINT runner_queue_cursors_slot_range CHECK (((runner_slot >= 1) AND (runner_slot <= 65535))),
    CONSTRAINT runner_queue_cursors_upper_complete CHECK (((cycle_upper_queued_at_ms IS NULL) = (cycle_upper_attempt_id IS NULL))),
    CONSTRAINT runner_queue_cursors_version_positive CHECK ((cursor_version > 0))
);

CREATE TABLE runner_rpc_receipts (
    runner_session_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_epoch bigint NOT NULL,
    runner_generation bigint NOT NULL,
    operation_kind text NOT NULL,
    request_digest bytea NOT NULL,
    response_schema integer NOT NULL,
    response_digest bytea NOT NULL,
    committed_at_ms bigint NOT NULL,
    tenant_id text NOT NULL,
    response_plaintext_size_bytes bigint NOT NULL,
    envelope_schema integer,
    wrapping_key_id text,
    wrapped_data_key bytea,
    nonce bytea,
    ciphertext bytea,
    payload_tombstone_reason text,
    payload_tombstoned_at_ms bigint,
    lease_offer_request_operation_id uuid,
    lease_offer_command_sequence bigint,
    lease_offer_response_disposition text,
    lease_offer_primary_response_schema integer,
    lease_offer_primary_response_digest bytea,
    lease_offer_fallback_version integer,
    lease_offer_fallback_operation_id uuid,
    lease_offer_fallback_retry_after_millis bigint,
    lease_offer_fallback_response_schema integer,
    lease_offer_fallback_response_digest bytea,
    CONSTRAINT runner_rpc_receipts_ciphertext_size CHECK ((((octet_length(ciphertext))::numeric = ((response_plaintext_size_bytes)::numeric + (16)::numeric)) AND (octet_length(ciphertext) <= 16777232))),
    CONSTRAINT runner_rpc_receipts_envelope_schema_v1 CHECK ((envelope_schema = 1)),
    CONSTRAINT runner_rpc_receipts_kind_shape CHECK ((((octet_length(operation_kind) >= 1) AND (octet_length(operation_kind) <= 128)) AND (operation_kind ~ '^[a-z0-9][a-z0-9._/-]*$'::text))),
    CONSTRAINT runner_rpc_receipts_lease_offer_binding_shape CHECK ((((lease_offer_request_operation_id IS NULL) AND (lease_offer_command_sequence IS NULL)) OR ((operation_kind = 'automata.runner.lease-request.v1'::text) AND (lease_offer_request_operation_id = operation_id) AND (lease_offer_command_sequence > 0)))),
    CONSTRAINT runner_rpc_receipts_lease_offer_completion_shape CHECK ((((lease_offer_request_operation_id IS NULL) AND (lease_offer_command_sequence IS NULL) AND (lease_offer_response_disposition IS NULL) AND (lease_offer_primary_response_schema IS NULL) AND (lease_offer_primary_response_digest IS NULL) AND (lease_offer_fallback_version IS NULL) AND (lease_offer_fallback_operation_id IS NULL) AND (lease_offer_fallback_retry_after_millis IS NULL) AND (lease_offer_fallback_response_schema IS NULL) AND (lease_offer_fallback_response_digest IS NULL)) OR ((lease_offer_request_operation_id IS NOT NULL) AND (lease_offer_command_sequence IS NOT NULL) AND (lease_offer_response_disposition IS NOT NULL) AND (lease_offer_primary_response_schema IS NOT NULL) AND (lease_offer_primary_response_digest IS NOT NULL) AND (lease_offer_fallback_version IS NOT NULL) AND (lease_offer_fallback_operation_id IS NOT NULL) AND (lease_offer_fallback_retry_after_millis IS NOT NULL) AND (lease_offer_fallback_response_schema IS NOT NULL) AND (lease_offer_fallback_response_digest IS NOT NULL) AND (lease_offer_response_disposition = ANY (ARRAY['primary'::text, 'revoked_fallback'::text])) AND ((lease_offer_primary_response_schema >= 1) AND (lease_offer_primary_response_schema <= 65535)) AND (octet_length(lease_offer_primary_response_digest) = 32) AND (lease_offer_fallback_version = 1) AND (lease_offer_fallback_operation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((lease_offer_fallback_retry_after_millis >= 1) AND (lease_offer_fallback_retry_after_millis <= '4294967295'::bigint)) AND ((lease_offer_fallback_response_schema >= 1) AND (lease_offer_fallback_response_schema <= 65535)) AND (octet_length(lease_offer_fallback_response_digest) = 32) AND (((lease_offer_response_disposition = 'primary'::text) AND (response_schema = lease_offer_primary_response_schema) AND (response_digest = lease_offer_primary_response_digest)) OR ((lease_offer_response_disposition = 'revoked_fallback'::text) AND (response_schema = lease_offer_fallback_response_schema) AND (response_digest = lease_offer_fallback_response_digest)))))),
    CONSTRAINT runner_rpc_receipts_nonce_size CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT runner_rpc_receipts_payload_lifecycle CHECK ((((payload_tombstone_reason IS NULL) AND (payload_tombstoned_at_ms IS NULL) AND (envelope_schema IS NOT NULL) AND (wrapping_key_id IS NOT NULL) AND (wrapped_data_key IS NOT NULL) AND (nonce IS NOT NULL) AND (ciphertext IS NOT NULL)) OR ((payload_tombstone_reason = ANY (ARRAY['session_closed'::text, 'session_superseded'::text])) AND (payload_tombstoned_at_ms IS NOT NULL) AND (payload_tombstoned_at_ms >= committed_at_ms) AND (envelope_schema IS NULL) AND (wrapping_key_id IS NULL) AND (wrapped_data_key IS NULL) AND (nonce IS NULL) AND (ciphertext IS NULL)))),
    CONSTRAINT runner_rpc_receipts_plaintext_size_range CHECK (((response_plaintext_size_bytes >= 1) AND (response_plaintext_size_bytes <= 16777216))),
    CONSTRAINT runner_rpc_receipts_request_sha256 CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT runner_rpc_receipts_response_schema CHECK (((response_schema >= 1) AND (response_schema <= 65535))),
    CONSTRAINT runner_rpc_receipts_response_sha256 CHECK ((octet_length(response_digest) = 32)),
    CONSTRAINT runner_rpc_receipts_wrapped_data_key_size CHECK (((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 65536))),
    CONSTRAINT runner_rpc_receipts_wrapping_key_id_canonical CHECK ((((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 64)) AND (wrapping_key_id ~ '^[a-z0-9][a-z0-9._-]*$'::text) AND ("right"(wrapping_key_id, 1) ~ '^[a-z0-9]$'::text)))
);

CREATE TABLE runner_sessions (
    id uuid NOT NULL,
    runner_id uuid NOT NULL,
    protocol_version integer NOT NULL,
    job_ir_schema integer NOT NULL,
    capability_snapshot jsonb NOT NULL,
    connected_at_ms bigint NOT NULL,
    heartbeat_at_ms bigint NOT NULL,
    disconnected_at_ms bigint,
    runner_generation bigint NOT NULL,
    session_epoch bigint NOT NULL,
    last_command_sequence bigint DEFAULT 0 NOT NULL,
    acknowledged_command_sequence bigint DEFAULT 0 NOT NULL,
    CONSTRAINT runner_sessions_command_cursor_valid CHECK (((acknowledged_command_sequence >= 0) AND (acknowledged_command_sequence <= last_command_sequence))),
    CONSTRAINT runner_sessions_command_sequence_nonnegative CHECK ((last_command_sequence >= 0)),
    CONSTRAINT runner_sessions_disconnect_monotonic CHECK (((disconnected_at_ms IS NULL) OR (disconnected_at_ms >= heartbeat_at_ms))),
    CONSTRAINT runner_sessions_epoch_positive CHECK ((session_epoch > 0)),
    CONSTRAINT runner_sessions_generation_positive CHECK ((runner_generation > 0)),
    CONSTRAINT runner_sessions_heartbeat_monotonic CHECK ((heartbeat_at_ms >= connected_at_ms)),
    CONSTRAINT runner_sessions_job_ir_current CHECK ((job_ir_schema = 1)),
    CONSTRAINT runner_sessions_protocol_current CHECK ((protocol_version = 1))
);

CREATE TABLE runners (
    id uuid NOT NULL,
    tenant_id text NOT NULL,
    group_id uuid,
    name text NOT NULL,
    normalized_name text NOT NULL,
    labels text[] DEFAULT '{}'::text[] NOT NULL,
    capabilities jsonb NOT NULL,
    slots integer NOT NULL,
    status text NOT NULL,
    generation bigint DEFAULT 1 NOT NULL,
    last_seen_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    session_epoch bigint DEFAULT 0 NOT NULL,
    external_identity text,
    desired_state text NOT NULL,
    CONSTRAINT runners_desired_state CHECK ((desired_state = ANY (ARRAY['active'::text, 'draining'::text, 'disabled'::text]))),
    CONSTRAINT runners_external_identity_shape CHECK (((external_identity IS NULL) OR (((octet_length(external_identity) >= 1) AND (octet_length(external_identity) <= 255)) AND (external_identity !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT runners_generation_positive CHECK ((generation > 0)),
    CONSTRAINT runners_session_epoch_nonnegative CHECK ((session_epoch >= 0)),
    CONSTRAINT runners_slots_positive CHECK ((slots > 0)),
    CONSTRAINT runners_slots_u16 CHECK ((slots <= 65535)),
    CONSTRAINT runners_status CHECK ((status = ANY (ARRAY['offline'::text, 'online'::text])))
);

CREATE TABLE secret_cleanup_outbox (
    sequence bigint NOT NULL,
    operation_id uuid NOT NULL,
    tenant_id text NOT NULL,
    provider_id text NOT NULL,
    cleanup_kind text NOT NULL,
    provider_lease_record_id uuid,
    secret_id uuid,
    secret_version_id uuid,
    version_number bigint,
    envelope_generation bigint,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at_ms bigint NOT NULL,
    locked_by text,
    locked_at_ms bigint,
    last_failure_kind text,
    created_at_ms bigint NOT NULL,
    completed_at_ms bigint,
    claim_generation bigint DEFAULT 0 NOT NULL,
    CONSTRAINT secret_cleanup_outbox_attempts_bounded CHECK (((attempts >= 0) AND (attempts <= 100))),
    CONSTRAINT secret_cleanup_outbox_claim_generation CHECK (((claim_generation >= 0) AND (claim_generation >= attempts) AND (((attempts = 0) AND (claim_generation = 0)) OR ((attempts > 0) AND (claim_generation > 0))))),
    CONSTRAINT secret_cleanup_outbox_completion_shape CHECK (((((status = 'completed'::text) AND (completed_at_ms >= created_at_ms)) OR ((status <> 'completed'::text) AND (completed_at_ms IS NULL))) IS TRUE)),
    CONSTRAINT secret_cleanup_outbox_failure_kind CHECK (((last_failure_kind IS NULL) OR (last_failure_kind = ANY (ARRAY['invalid_request'::text, 'unsupported'::text, 'unauthorized'::text, 'forbidden'::text, 'not_found'::text, 'conflict'::text, 'rate_limited'::text, 'unavailable'::text, 'integrity_failure'::text, 'invalid_response'::text])))),
    CONSTRAINT secret_cleanup_outbox_kind CHECK ((cleanup_kind = ANY (ARRAY['revoke_provider_lease'::text, 'destroy_secret_version'::text, 'retire_envelope'::text]))),
    CONSTRAINT secret_cleanup_outbox_lock_shape CHECK (((((status = 'in_progress'::text) AND ((octet_length(locked_by) >= 1) AND (octet_length(locked_by) <= 255)) AND (locked_by !~ '[[:cntrl:]]'::text) AND (locked_at_ms IS NOT NULL) AND (completed_at_ms IS NULL)) OR ((status <> 'in_progress'::text) AND (locked_by IS NULL) AND (locked_at_ms IS NULL))) IS TRUE)),
    CONSTRAINT secret_cleanup_outbox_status CHECK ((status = ANY (ARRAY['pending'::text, 'in_progress'::text, 'completed'::text, 'dead_letter'::text]))),
    CONSTRAINT secret_cleanup_outbox_target_shape CHECK (((((cleanup_kind = 'revoke_provider_lease'::text) AND (provider_lease_record_id IS NOT NULL) AND (secret_id IS NULL) AND (secret_version_id IS NULL) AND (version_number IS NULL) AND (envelope_generation IS NULL)) OR ((cleanup_kind = 'destroy_secret_version'::text) AND (provider_lease_record_id IS NULL) AND (secret_id IS NOT NULL) AND (secret_version_id IS NOT NULL) AND (version_number IS NOT NULL) AND (envelope_generation IS NULL)) OR ((cleanup_kind = 'retire_envelope'::text) AND (provider_lease_record_id IS NULL) AND (secret_id IS NOT NULL) AND (secret_version_id IS NOT NULL) AND (version_number IS NOT NULL) AND (envelope_generation IS NOT NULL))) IS TRUE)),
    CONSTRAINT secret_cleanup_outbox_time_order CHECK ((next_attempt_at_ms >= created_at_ms))
);

ALTER TABLE secret_cleanup_outbox ALTER COLUMN sequence ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME secret_cleanup_outbox_sequence_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE secret_custody_key_canaries (
    wrapping_key_id text NOT NULL COLLATE pg_catalog."C",
    canary_generation bigint DEFAULT 1 NOT NULL,
    canary_schema integer DEFAULT 1 NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    envelope_schema integer NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT secret_custody_key_canaries_canary_schema CHECK ((canary_schema = 1)),
    CONSTRAINT secret_custody_key_canaries_ciphertext_shape CHECK ((octet_length(ciphertext) = 52)),
    CONSTRAINT secret_custody_key_canaries_envelope_schema CHECK ((envelope_schema = 1)),
    CONSTRAINT secret_custody_key_canaries_generation CHECK ((canary_generation = 1)),
    CONSTRAINT secret_custody_key_canaries_key_id_shape CHECK ((((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 64)) AND (wrapping_key_id ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'::text))),
    CONSTRAINT secret_custody_key_canaries_nonce_shape CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT secret_custody_key_canaries_time_nonnegative CHECK ((created_at_ms >= 0)),
    CONSTRAINT secret_custody_key_canaries_wrapped_key_shape CHECK (((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 4096)))
);

CREATE TABLE secret_key_rotation_items (
    tenant_id text NOT NULL,
    rotation_id uuid NOT NULL,
    secret_version_id uuid NOT NULL,
    secret_id uuid NOT NULL,
    version_number bigint NOT NULL,
    previous_envelope_generation bigint NOT NULL,
    replacement_envelope_generation bigint,
    status text DEFAULT 'pending'::text NOT NULL,
    failure_kind text,
    created_at_ms bigint NOT NULL,
    completed_at_ms bigint,
    CONSTRAINT secret_key_rotation_items_status CHECK ((status = ANY (ARRAY['pending'::text, 'completed'::text, 'failed'::text]))),
    CONSTRAINT secret_key_rotation_items_status_shape CHECK (((((status = 'pending'::text) AND (replacement_envelope_generation IS NULL) AND (failure_kind IS NULL) AND (completed_at_ms IS NULL)) OR ((status = 'completed'::text) AND (replacement_envelope_generation IS NOT NULL) AND (replacement_envelope_generation <> previous_envelope_generation) AND (failure_kind IS NULL) AND (completed_at_ms >= created_at_ms)) OR ((status = 'failed'::text) AND (failure_kind = ANY (ARRAY['invalid_request'::text, 'unsupported'::text, 'unauthorized'::text, 'forbidden'::text, 'not_found'::text, 'conflict'::text, 'rate_limited'::text, 'unavailable'::text, 'integrity_failure'::text, 'invalid_response'::text, 'key_unavailable'::text, 'encryption_failure'::text, 'decryption_failure'::text, 'storage_failure'::text])) AND (completed_at_ms >= created_at_ms))) IS TRUE))
);

CREATE TABLE secret_key_rotations (
    tenant_id text NOT NULL,
    id uuid NOT NULL,
    provider_id text NOT NULL,
    from_wrapping_key_id text NOT NULL,
    to_wrapping_key_id text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    discovered_versions bigint DEFAULT 0 NOT NULL,
    completed_versions bigint DEFAULT 0 NOT NULL,
    initiated_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    started_at_ms bigint,
    completed_at_ms bigint,
    failure_kind text,
    revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT secret_key_rotations_key_ids_shape CHECK ((((octet_length(from_wrapping_key_id) >= 1) AND (octet_length(from_wrapping_key_id) <= 128)) AND (from_wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'::text) AND ((octet_length(to_wrapping_key_id) >= 1) AND (octet_length(to_wrapping_key_id) <= 128)) AND (to_wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'::text) AND (from_wrapping_key_id <> to_wrapping_key_id))),
    CONSTRAINT secret_key_rotations_progress CHECK (((discovered_versions >= 0) AND ((completed_versions >= 0) AND (completed_versions <= discovered_versions)))),
    CONSTRAINT secret_key_rotations_revision_positive CHECK ((revision > 0)),
    CONSTRAINT secret_key_rotations_status CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text]))),
    CONSTRAINT secret_key_rotations_status_shape CHECK (((((status = 'pending'::text) AND (started_at_ms IS NULL) AND (completed_at_ms IS NULL) AND (failure_kind IS NULL)) OR ((status = 'running'::text) AND (started_at_ms >= created_at_ms) AND (completed_at_ms IS NULL) AND (failure_kind IS NULL)) OR ((status = 'completed'::text) AND (started_at_ms >= created_at_ms) AND (completed_at_ms >= started_at_ms) AND (completed_versions = discovered_versions) AND (failure_kind IS NULL)) OR ((status = 'failed'::text) AND (started_at_ms >= created_at_ms) AND (completed_at_ms >= started_at_ms) AND (failure_kind = ANY (ARRAY['invalid_request'::text, 'unsupported'::text, 'unauthorized'::text, 'forbidden'::text, 'not_found'::text, 'conflict'::text, 'rate_limited'::text, 'unavailable'::text, 'integrity_failure'::text, 'invalid_response'::text, 'key_unavailable'::text, 'encryption_failure'::text, 'decryption_failure'::text, 'storage_failure'::text])))) IS TRUE))
);

CREATE TABLE secret_mutation_recovery_outbox (
    sequence bigint NOT NULL,
    operation_id uuid NOT NULL,
    tenant_id text NOT NULL,
    mutation_id uuid NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at_ms bigint NOT NULL,
    claim_generation bigint DEFAULT 0 NOT NULL,
    locked_by text,
    locked_at_ms bigint,
    completed_by text,
    completed_claim_generation bigint,
    completed_locked_at_ms bigint,
    resolution text,
    created_at_ms bigint NOT NULL,
    completed_at_ms bigint,
    CONSTRAINT secret_mutation_recovery_outbox_attempts CHECK (((attempts >= 0) AND (attempts <= 1))),
    CONSTRAINT secret_mutation_recovery_outbox_generation CHECK (((claim_generation >= 0) AND ((completed_claim_generation IS NULL) OR (completed_claim_generation > 0)))),
    CONSTRAINT secret_mutation_recovery_outbox_lock_shape CHECK (((((status = 'in_progress'::text) AND (attempts = 1) AND (claim_generation > 0) AND ((octet_length(locked_by) >= 1) AND (octet_length(locked_by) <= 255)) AND (locked_by !~ '[[:cntrl:]]'::text) AND (locked_at_ms >= next_attempt_at_ms) AND (completed_at_ms IS NULL) AND (completed_by IS NULL) AND (completed_claim_generation IS NULL) AND (completed_locked_at_ms IS NULL) AND (resolution IS NULL)) OR ((status = 'pending'::text) AND (attempts = 0) AND (claim_generation = 0) AND (locked_by IS NULL) AND (locked_at_ms IS NULL) AND (completed_at_ms IS NULL) AND (completed_by IS NULL) AND (completed_claim_generation IS NULL) AND (completed_locked_at_ms IS NULL) AND (resolution IS NULL)) OR ((status = 'completed'::text) AND (completed_at_ms >= created_at_ms) AND (((resolution = 'human_terminal'::text) AND (claim_generation >= 0) AND (locked_by IS NULL) AND (locked_at_ms IS NULL) AND (completed_by IS NULL) AND (completed_claim_generation IS NULL) AND (completed_locked_at_ms IS NULL)) OR ((resolution = ANY (ARRAY['expired_without_stage'::text, 'expired_with_cleanup'::text])) AND (attempts = 1) AND (claim_generation > 0) AND (locked_by IS NULL) AND (locked_at_ms IS NULL) AND ((octet_length(completed_by) >= 1) AND (octet_length(completed_by) <= 255)) AND (completed_by !~ '[[:cntrl:]]'::text) AND (completed_claim_generation = claim_generation) AND (completed_locked_at_ms >= next_attempt_at_ms))))) IS TRUE)),
    CONSTRAINT secret_mutation_recovery_outbox_non_nil CHECK ((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT secret_mutation_recovery_outbox_operation_exact CHECK ((operation_id = automata_secret_mutation_recovery_operation_id(tenant_id, mutation_id))),
    CONSTRAINT secret_mutation_recovery_outbox_status CHECK ((status = ANY (ARRAY['pending'::text, 'in_progress'::text, 'completed'::text]))),
    CONSTRAINT secret_mutation_recovery_outbox_time CHECK ((next_attempt_at_ms >= created_at_ms))
);

ALTER TABLE secret_mutation_recovery_outbox ALTER COLUMN sequence ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME secret_mutation_recovery_outbox_sequence_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE secret_provider_configuration_envelope_heads (
    tenant_id text NOT NULL,
    provider_id text CONSTRAINT secret_provider_configuration_envelope_hea_provider_id_not_null NOT NULL,
    envelope_generation bigint CONSTRAINT secret_provider_configuration_env_envelope_generation_not_null1 NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_at_ms bigint CONSTRAINT secret_provider_configuration_envelope_h_updated_at_ms_not_null NOT NULL,
    CONSTRAINT secret_provider_configuration_envelope_heads_revision_positive CHECK ((revision > 0))
);

CREATE TABLE secret_provider_configuration_envelopes (
    tenant_id text NOT NULL,
    provider_id text NOT NULL,
    envelope_generation bigint CONSTRAINT secret_provider_configuration_enve_envelope_generation_not_null NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    wrapped_data_key bytea CONSTRAINT secret_provider_configuration_envelop_wrapped_data_key_not_null NOT NULL,
    wrapping_key_id text CONSTRAINT secret_provider_configuration_envelope_wrapping_key_id_not_null NOT NULL,
    envelope_schema integer CONSTRAINT secret_provider_configuration_envelope_envelope_schema_not_null NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT secret_provider_configuration_envelopes_ciphertext_shape CHECK (((octet_length(ciphertext) >= 1) AND (octet_length(ciphertext) <= 131072))),
    CONSTRAINT secret_provider_configuration_envelopes_generation_positive CHECK ((envelope_generation > 0)),
    CONSTRAINT secret_provider_configuration_envelopes_key_id_shape CHECK ((((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 128)) AND (wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'::text))),
    CONSTRAINT secret_provider_configuration_envelopes_nonce_shape CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT secret_provider_configuration_envelopes_schema CHECK ((envelope_schema = 1)),
    CONSTRAINT secret_provider_configuration_envelopes_wrapped_key_shape CHECK (((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 4096)))
);

CREATE TABLE secret_provider_lease_envelope_heads (
    tenant_id text NOT NULL,
    provider_lease_record_id uuid CONSTRAINT secret_provider_lease_envelo_provider_lease_record_id_not_null1 NOT NULL,
    envelope_generation bigint CONSTRAINT secret_provider_lease_envelope_hea_envelope_generation_not_null NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT secret_provider_lease_envelope_heads_revision_positive CHECK ((revision > 0))
);

CREATE TABLE secret_provider_lease_envelopes (
    tenant_id text NOT NULL,
    provider_lease_record_id uuid CONSTRAINT secret_provider_lease_envelop_provider_lease_record_id_not_null NOT NULL,
    provider_id text NOT NULL,
    envelope_generation bigint NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    wrapping_key_id text NOT NULL,
    envelope_schema integer NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT secret_provider_lease_envelopes_ciphertext_shape CHECK (((octet_length(ciphertext) >= 1) AND (octet_length(ciphertext) <= 131072))),
    CONSTRAINT secret_provider_lease_envelopes_generation_positive CHECK ((envelope_generation > 0)),
    CONSTRAINT secret_provider_lease_envelopes_key_id_shape CHECK ((((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 128)) AND (wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'::text))),
    CONSTRAINT secret_provider_lease_envelopes_nonce_shape CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT secret_provider_lease_envelopes_schema CHECK ((envelope_schema = 1)),
    CONSTRAINT secret_provider_lease_envelopes_wrapped_key_shape CHECK (((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 4096)))
);

CREATE TABLE secret_provider_leases (
    tenant_id text NOT NULL,
    id uuid NOT NULL,
    provider_id text NOT NULL,
    workload_grant_id uuid NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    issued_at_seconds bigint NOT NULL,
    expires_at_seconds bigint NOT NULL,
    renewed_at_seconds bigint,
    revoked_at_seconds bigint,
    revocation_reason text,
    revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT secret_provider_leases_lifetime CHECK (((issued_at_seconds > 0) AND (expires_at_seconds > issued_at_seconds) AND ((renewed_at_seconds IS NULL) OR (renewed_at_seconds >= issued_at_seconds)))),
    CONSTRAINT secret_provider_leases_revision_positive CHECK ((revision > 0)),
    CONSTRAINT secret_provider_leases_revocation_shape CHECK (((((status = 'active'::text) AND (revoked_at_seconds IS NULL) AND (revocation_reason IS NULL)) OR ((status = 'revocation_pending'::text) AND (revoked_at_seconds IS NULL) AND (revocation_reason = ANY (ARRAY['grant_revoked'::text, 'provider_revocation_requested'::text, 'secret_destroyed'::text, 'administrative_revocation'::text, 'integrity_failure'::text]))) OR ((status = 'revoked'::text) AND (revoked_at_seconds >= issued_at_seconds) AND (revocation_reason = ANY (ARRAY['grant_revoked'::text, 'provider_revoked'::text, 'secret_destroyed'::text, 'administrative_revocation'::text, 'integrity_failure'::text]))) OR ((status = 'expired'::text) AND (revoked_at_seconds >= issued_at_seconds) AND (revocation_reason = 'lease_expired'::text))) IS TRUE)),
    CONSTRAINT secret_provider_leases_status CHECK ((status = ANY (ARRAY['active'::text, 'revocation_pending'::text, 'revoked'::text, 'expired'::text])))
);

CREATE TABLE secret_provider_locator_envelope_heads (
    tenant_id text NOT NULL,
    secret_id uuid NOT NULL,
    envelope_generation bigint CONSTRAINT secret_provider_locator_envelope_h_envelope_generation_not_null NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT secret_provider_locator_envelope_heads_revision_positive CHECK ((revision > 0))
);

CREATE TABLE secret_provider_locator_envelopes (
    tenant_id text NOT NULL,
    secret_id uuid NOT NULL,
    provider_id text NOT NULL,
    envelope_generation bigint NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    wrapping_key_id text NOT NULL,
    envelope_schema integer NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT secret_provider_locator_envelopes_ciphertext_shape CHECK (((octet_length(ciphertext) >= 1) AND (octet_length(ciphertext) <= 131072))),
    CONSTRAINT secret_provider_locator_envelopes_generation_positive CHECK ((envelope_generation > 0)),
    CONSTRAINT secret_provider_locator_envelopes_key_id_shape CHECK ((((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 128)) AND (wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'::text))),
    CONSTRAINT secret_provider_locator_envelopes_nonce_shape CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT secret_provider_locator_envelopes_schema CHECK ((envelope_schema = 1)),
    CONSTRAINT secret_provider_locator_envelopes_wrapped_key_shape CHECK (((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 4096)))
);

CREATE TABLE secret_provider_version_envelope_heads (
    tenant_id text NOT NULL,
    secret_version_id uuid CONSTRAINT secret_provider_version_envelope_hea_secret_version_id_not_null NOT NULL,
    envelope_generation bigint CONSTRAINT secret_provider_version_envelope_h_envelope_generation_not_null NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT secret_provider_version_envelope_heads_revision_positive CHECK ((revision > 0))
);

CREATE TABLE secret_provider_version_envelopes (
    tenant_id text NOT NULL,
    secret_version_id uuid NOT NULL,
    secret_id uuid NOT NULL,
    version_number bigint NOT NULL,
    provider_id text NOT NULL,
    envelope_generation bigint NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    wrapping_key_id text NOT NULL,
    envelope_schema integer NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT secret_provider_version_envelopes_ciphertext_shape CHECK (((octet_length(ciphertext) >= 1) AND (octet_length(ciphertext) <= 131072))),
    CONSTRAINT secret_provider_version_envelopes_generation_positive CHECK ((envelope_generation > 0)),
    CONSTRAINT secret_provider_version_envelopes_key_id_shape CHECK ((((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 128)) AND (wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'::text))),
    CONSTRAINT secret_provider_version_envelopes_nonce_shape CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT secret_provider_version_envelopes_schema CHECK ((envelope_schema = 1)),
    CONSTRAINT secret_provider_version_envelopes_wrapped_key_shape CHECK (((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 4096)))
);

CREATE TABLE secret_providers (
    tenant_id text NOT NULL,
    provider_id text NOT NULL,
    adapter_kind text NOT NULL,
    display_name text NOT NULL,
    supports_create_version boolean NOT NULL,
    supports_destroy_version boolean NOT NULL,
    supports_dynamic_leases boolean NOT NULL,
    supports_renew_leases boolean NOT NULL,
    supports_revoke_leases boolean NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    status text DEFAULT 'unconfigured'::text NOT NULL,
    health text DEFAULT 'unknown'::text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT secret_providers_adapter_kind_shape CHECK ((((octet_length(adapter_kind) >= 1) AND (octet_length(adapter_kind) <= 128)) AND (adapter_kind ~ '^[a-z0-9][a-z0-9._:-]*$'::text))),
    CONSTRAINT secret_providers_capability_dependencies CHECK ((((NOT supports_renew_leases) OR supports_dynamic_leases) AND ((NOT supports_revoke_leases) OR supports_dynamic_leases))),
    CONSTRAINT secret_providers_display_name_shape CHECK ((((octet_length(display_name) >= 1) AND (octet_length(display_name) <= 255)) AND (display_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT secret_providers_health CHECK ((health = ANY (ARRAY['unknown'::text, 'healthy'::text, 'degraded'::text, 'unavailable'::text]))),
    CONSTRAINT secret_providers_id_shape CHECK ((((octet_length(provider_id) >= 1) AND (octet_length(provider_id) <= 64)) AND (provider_id ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'::text))),
    CONSTRAINT secret_providers_revision_positive CHECK ((revision > 0)),
    CONSTRAINT secret_providers_status CHECK ((status = ANY (ARRAY['unconfigured'::text, 'active'::text, 'disabled'::text]))),
    CONSTRAINT secret_providers_time_monotonic CHECK ((updated_at_ms >= created_at_ms))
);

CREATE TABLE secret_repository_access (
    tenant_id text NOT NULL,
    secret_id uuid NOT NULL,
    secret_scope_kind text DEFAULT 'tenant'::text NOT NULL,
    repository_id uuid NOT NULL,
    granted_by_principal_id uuid,
    granted_at_ms bigint NOT NULL,
    CONSTRAINT secret_repository_access_tenant_scope CHECK ((secret_scope_kind = 'tenant'::text))
);

CREATE TABLE secret_version_envelope_heads (
    tenant_id text NOT NULL,
    secret_version_id uuid NOT NULL,
    envelope_generation bigint NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT secret_version_envelope_heads_revision_positive CHECK ((revision > 0))
);

CREATE TABLE secret_version_envelopes (
    tenant_id text NOT NULL,
    secret_version_id uuid NOT NULL,
    secret_id uuid NOT NULL,
    version_number bigint NOT NULL,
    storage_kind text DEFAULT 'built_in_ciphertext'::text NOT NULL,
    envelope_generation bigint NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    wrapping_key_id text NOT NULL COLLATE pg_catalog."C",
    envelope_schema integer NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT secret_version_envelopes_ciphertext_shape CHECK (((octet_length(ciphertext) >= 1) AND (octet_length(ciphertext) <= 131072))),
    CONSTRAINT secret_version_envelopes_generation_positive CHECK ((envelope_generation > 0)),
    CONSTRAINT secret_version_envelopes_key_id_shape CHECK ((((octet_length(wrapping_key_id) >= 1) AND (octet_length(wrapping_key_id) <= 64)) AND (wrapping_key_id ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'::text))),
    CONSTRAINT secret_version_envelopes_nonce_shape CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT secret_version_envelopes_schema CHECK ((envelope_schema = 1)),
    CONSTRAINT secret_version_envelopes_storage_kind CHECK ((storage_kind = 'built_in_ciphertext'::text)),
    CONSTRAINT secret_version_envelopes_wrapped_key_shape CHECK (((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 4096)))
);

CREATE TABLE secret_version_lifecycle (
    tenant_id text NOT NULL,
    secret_version_id uuid NOT NULL,
    secret_id uuid NOT NULL,
    version_number bigint NOT NULL,
    provider_id text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    destroy_request_id text,
    revision bigint DEFAULT 1 NOT NULL,
    changed_by_principal_id uuid,
    changed_at_ms bigint NOT NULL,
    destroyed_at_ms bigint,
    mutation_id uuid NOT NULL,
    CONSTRAINT secret_version_lifecycle_destroy_shape CHECK (((((status = ANY (ARRAY['staged'::text, 'active'::text, 'superseded'::text, 'disabled'::text])) AND (destroy_request_id IS NULL) AND (destroyed_at_ms IS NULL)) OR ((status = 'destroy_pending'::text) AND ((octet_length(destroy_request_id) >= 1) AND (octet_length(destroy_request_id) <= 255)) AND (destroy_request_id !~ '[[:cntrl:]]'::text) AND (destroyed_at_ms IS NULL)) OR ((status = 'destroyed'::text) AND ((octet_length(destroy_request_id) >= 1) AND (octet_length(destroy_request_id) <= 255)) AND (destroy_request_id !~ '[[:cntrl:]]'::text) AND (destroyed_at_ms >= changed_at_ms))) IS TRUE)),
    CONSTRAINT secret_version_lifecycle_revision_positive CHECK ((revision > 0)),
    CONSTRAINT secret_version_lifecycle_staged_mutation CHECK (((status <> 'staged'::text) OR (mutation_id IS NOT NULL))),
    CONSTRAINT secret_version_lifecycle_status CHECK ((status = ANY (ARRAY['staged'::text, 'active'::text, 'superseded'::text, 'disabled'::text, 'destroy_pending'::text, 'destroyed'::text])))
);

CREATE TABLE secret_version_mutations (
    tenant_id text NOT NULL,
    mutation_id uuid NOT NULL,
    secret_id uuid NOT NULL,
    scope_kind text NOT NULL,
    repository_id uuid,
    environment_id uuid,
    canonical_name text NOT NULL,
    provider_id text NOT NULL,
    requested_provider_id text,
    mutation_kind text NOT NULL,
    expected_secret_revision bigint,
    reserved_secret_revision bigint NOT NULL,
    expected_predecessor_version_id uuid,
    expected_predecessor_version_number bigint,
    provider_create_request_id text NOT NULL,
    state text DEFAULT 'reserved'::text NOT NULL,
    completion_kind text,
    committed_version_id uuid,
    committed_version_number bigint,
    confirmed_secret_revision bigint,
    reserved_by_principal_id uuid NOT NULL,
    reserved_at_ms bigint NOT NULL,
    confirmed_by_principal_id uuid,
    confirmed_at_ms bigint,
    terminal_reason text,
    revision bigint DEFAULT 1 NOT NULL,
    reserved_version_number bigint NOT NULL,
    confirmation_deadline_ms bigint NOT NULL,
    reserved_by_session_id uuid NOT NULL,
    reserved_authorization_revision bigint CONSTRAINT secret_version_mutations_reserved_authorization_revisi_not_null NOT NULL,
    terminal_actor_kind text,
    confirmed_by_session_id uuid,
    confirmed_authorization_revision bigint,
    expiration_authority text,
    abandoned_version_id uuid,
    abandoned_version_number bigint,
    CONSTRAINT secret_version_mutations_completion_kind CHECK (((completion_kind IS NULL) OR (completion_kind = ANY (ARRAY['builtin_created'::text, 'cas_lost'::text, 'system_cancelled'::text, 'reservation_expired'::text])))),
    CONSTRAINT secret_version_mutations_confirmed_authorization_positive CHECK (((confirmed_authorization_revision IS NULL) OR (confirmed_authorization_revision > 0))),
    CONSTRAINT secret_version_mutations_deadline_exact CHECK ((confirmation_deadline_ms = (reserved_at_ms + 600000))),
    CONSTRAINT secret_version_mutations_expectation_shape CHECK (((((mutation_kind = 'create'::text) AND (expected_secret_revision IS NULL) AND (reserved_secret_revision = 1) AND (reserved_version_number = 1) AND (expected_predecessor_version_id IS NULL) AND (expected_predecessor_version_number IS NULL) AND ((requested_provider_id IS NULL) OR (requested_provider_id = provider_id))) OR ((mutation_kind = 'replace'::text) AND (expected_secret_revision > 0) AND (reserved_secret_revision = expected_secret_revision) AND (reserved_version_number > expected_predecessor_version_number) AND (expected_predecessor_version_id IS NOT NULL) AND (expected_predecessor_version_number > 0) AND (requested_provider_id IS NULL))) IS TRUE)),
    CONSTRAINT secret_version_mutations_expiration_authority CHECK (((expiration_authority IS NULL) OR (expiration_authority = ANY (ARRAY['current'::text, 'lost'::text])))),
    CONSTRAINT secret_version_mutations_kind CHECK ((mutation_kind = ANY (ARRAY['create'::text, 'replace'::text]))),
    CONSTRAINT secret_version_mutations_name_shape CHECK ((((octet_length(canonical_name) >= 1) AND (octet_length(canonical_name) <= 255)) AND (canonical_name ~ '^[A-Z_][A-Z0-9_]*$'::text) AND (canonical_name !~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'::text))),
    CONSTRAINT secret_version_mutations_non_nil_ids CHECK (((mutation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (secret_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (mutation_id <> secret_id) AND ((repository_id IS NULL) OR (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((environment_id IS NULL) OR (environment_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((expected_predecessor_version_id IS NULL) OR (expected_predecessor_version_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((committed_version_id IS NULL) OR (committed_version_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT secret_version_mutations_provider_request_shape CHECK ((((octet_length(provider_create_request_id) >= 1) AND (octet_length(provider_create_request_id) <= 255)) AND (provider_create_request_id = ('secret-version:'::text || (mutation_id)::text)))),
    CONSTRAINT secret_version_mutations_reserved_authorization_positive CHECK ((reserved_authorization_revision > 0)),
    CONSTRAINT secret_version_mutations_revision_positive CHECK ((revision > 0)),
    CONSTRAINT secret_version_mutations_scope_kind CHECK ((scope_kind = ANY (ARRAY['tenant'::text, 'repository'::text, 'environment'::text]))),
    CONSTRAINT secret_version_mutations_scope_shape CHECK (((((scope_kind = 'tenant'::text) AND (repository_id IS NULL) AND (environment_id IS NULL)) OR ((scope_kind = 'repository'::text) AND (repository_id IS NOT NULL) AND (environment_id IS NULL)) OR ((scope_kind = 'environment'::text) AND (repository_id IS NOT NULL) AND (environment_id IS NOT NULL))) IS TRUE)),
    CONSTRAINT secret_version_mutations_state CHECK ((state = ANY (ARRAY['reserved'::text, 'confirmed'::text, 'superseded'::text, 'cancelled'::text]))),
    CONSTRAINT secret_version_mutations_state_shape CHECK (((((state = 'reserved'::text) AND (completion_kind IS NULL) AND (committed_version_id IS NULL) AND (committed_version_number IS NULL) AND (confirmed_secret_revision IS NULL) AND (confirmed_by_principal_id IS NULL) AND (confirmed_by_session_id IS NULL) AND (confirmed_authorization_revision IS NULL) AND (confirmed_at_ms IS NULL) AND (terminal_actor_kind IS NULL) AND (terminal_reason IS NULL) AND (expiration_authority IS NULL) AND (abandoned_version_id IS NULL) AND (abandoned_version_number IS NULL)) OR ((state = 'confirmed'::text) AND (completion_kind = 'builtin_created'::text) AND (committed_version_id IS NOT NULL) AND (committed_version_number = reserved_version_number) AND (confirmed_secret_revision = (reserved_secret_revision + 1)) AND (confirmed_by_principal_id IS NOT NULL) AND (confirmed_by_session_id IS NOT NULL) AND (confirmed_authorization_revision IS NOT NULL) AND (confirmed_at_ms >= reserved_at_ms) AND (confirmed_at_ms < confirmation_deadline_ms) AND (terminal_actor_kind = 'human'::text) AND (terminal_reason IS NULL) AND (expiration_authority IS NULL) AND (abandoned_version_id IS NULL) AND (abandoned_version_number IS NULL)) OR ((state = 'superseded'::text) AND (completion_kind = 'builtin_created'::text) AND (committed_version_id IS NOT NULL) AND (committed_version_number = reserved_version_number) AND (confirmed_secret_revision = (reserved_secret_revision + 1)) AND (confirmed_by_principal_id IS NOT NULL) AND (confirmed_by_session_id IS NOT NULL) AND (confirmed_authorization_revision IS NOT NULL) AND (confirmed_at_ms >= reserved_at_ms) AND (confirmed_at_ms < confirmation_deadline_ms) AND (terminal_actor_kind = 'human'::text) AND (terminal_reason = ANY (ARRAY['applied_then_superseded'::text, 'applied_then_deleted'::text])) AND (expiration_authority IS NULL) AND (abandoned_version_id IS NULL) AND (abandoned_version_number IS NULL)) OR ((state = 'cancelled'::text) AND (completion_kind = ANY (ARRAY['cas_lost'::text, 'system_cancelled'::text])) AND (committed_version_id IS NULL) AND (committed_version_number IS NULL) AND (confirmed_secret_revision IS NULL) AND (confirmed_by_principal_id IS NOT NULL) AND (confirmed_by_session_id IS NOT NULL) AND (confirmed_authorization_revision IS NOT NULL) AND (confirmed_at_ms >= reserved_at_ms) AND (terminal_actor_kind = 'human'::text) AND (((completion_kind = 'cas_lost'::text) AND (confirmed_at_ms < confirmation_deadline_ms) AND (terminal_reason = 'cas_lost'::text)) OR ((completion_kind = 'system_cancelled'::text) AND (terminal_reason = 'secret_deleted'::text))) AND (expiration_authority IS NULL) AND (abandoned_version_id IS NULL) AND (abandoned_version_number IS NULL)) OR ((state = 'cancelled'::text) AND (completion_kind = 'reservation_expired'::text) AND (committed_version_id IS NULL) AND (committed_version_number IS NULL) AND (confirmed_secret_revision IS NULL) AND (confirmed_by_principal_id IS NULL) AND (confirmed_by_session_id IS NULL) AND (confirmed_authorization_revision IS NULL) AND (confirmed_at_ms >= confirmation_deadline_ms) AND (terminal_actor_kind = 'system'::text) AND (expiration_authority = ANY (ARRAY['current'::text, 'lost'::text])) AND (((terminal_reason = 'reservation_expired_no_stage'::text) AND (abandoned_version_id IS NULL) AND (abandoned_version_number IS NULL)) OR ((terminal_reason = 'reservation_expired_staged'::text) AND (abandoned_version_id IS NOT NULL) AND (abandoned_version_number = reserved_version_number))))) IS TRUE)),
    CONSTRAINT secret_version_mutations_terminal_actor CHECK (((terminal_actor_kind IS NULL) OR (terminal_actor_kind = ANY (ARRAY['human'::text, 'system'::text])))),
    CONSTRAINT secret_version_mutations_time_nonnegative CHECK ((reserved_at_ms >= 0))
);

CREATE TABLE secret_versions (
    tenant_id text NOT NULL,
    id uuid NOT NULL,
    secret_id uuid NOT NULL,
    version_number bigint NOT NULL,
    provider_id text NOT NULL,
    create_request_id text NOT NULL,
    storage_kind text NOT NULL,
    created_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    CONSTRAINT secret_versions_create_request_shape CHECK ((((octet_length(create_request_id) >= 1) AND (octet_length(create_request_id) <= 255)) AND (create_request_id !~ '[[:cntrl:]]'::text))),
    CONSTRAINT secret_versions_storage_kind CHECK ((storage_kind = ANY (ARRAY['built_in_ciphertext'::text, 'external_provider'::text]))),
    CONSTRAINT secret_versions_version_positive CHECK ((version_number > 0))
);

CREATE TABLE secret_workload_grants (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    run_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    secret_id uuid NOT NULL,
    secret_version_id uuid NOT NULL,
    secret_version_number bigint NOT NULL,
    provider_id text NOT NULL,
    environment_id uuid,
    environment_approval_request_id uuid,
    grant_mode text NOT NULL,
    event_trust text NOT NULL,
    source_kind text NOT NULL,
    authority_digest bytea NOT NULL,
    authority_digest_key_id text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    revocation_reason text,
    invocation_kind text DEFAULT 'direct'::text NOT NULL,
    reusable_secret_permission text DEFAULT 'none'::text NOT NULL,
    lease_id uuid,
    CONSTRAINT secret_workload_grants_authority_digest CHECK ((octet_length(authority_digest) = 32)),
    CONSTRAINT secret_workload_grants_authority_key_shape CHECK ((((octet_length(authority_digest_key_id) >= 1) AND (octet_length(authority_digest_key_id) <= 128)) AND (authority_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))),
    CONSTRAINT secret_workload_grants_environment_shape CHECK (((environment_id IS NOT NULL) OR (environment_approval_request_id IS NULL))),
    CONSTRAINT secret_workload_grants_event_trust CHECK ((event_trust = ANY (ARRAY['trusted'::text, 'untrusted'::text]))),
    CONSTRAINT secret_workload_grants_fencing_token_positive CHECK ((fencing_token > 0)),
    CONSTRAINT secret_workload_grants_grant_mode CHECK ((grant_mode = ANY (ARRAY['readable_secret'::text, 'capability_only'::text]))),
    CONSTRAINT secret_workload_grants_invocation_kind CHECK ((invocation_kind = ANY (ARRAY['direct'::text, 'reusable'::text]))),
    CONSTRAINT secret_workload_grants_lifetime CHECK ((expires_at_ms > issued_at_ms)),
    CONSTRAINT secret_workload_grants_reusable_permission CHECK (((reusable_secret_permission = ANY (ARRAY['none'::text, 'explicit'::text])) AND ((invocation_kind = 'reusable'::text) OR (reusable_secret_permission = 'none'::text)))),
    CONSTRAINT secret_workload_grants_revocation_shape CHECK (((((status = 'active'::text) AND (revoked_at_ms IS NULL) AND (revocation_reason IS NULL)) OR ((status = 'revoked'::text) AND (revoked_at_ms >= issued_at_ms) AND (revocation_reason = ANY (ARRAY['attempt_completed'::text, 'attempt_cancelled'::text, 'secret_disabled'::text, 'secret_deleted'::text, 'policy_changed'::text, 'environment_revoked'::text, 'administrative_revocation'::text, 'integrity_failure'::text]))) OR ((status = 'expired'::text) AND (revoked_at_ms >= issued_at_ms) AND (revocation_reason = 'grant_expired'::text))) IS TRUE)),
    CONSTRAINT secret_workload_grants_source_kind CHECK ((source_kind = ANY (ARRAY['same_repository'::text, 'fork'::text, 'dependabot'::text, 'unknown'::text]))),
    CONSTRAINT secret_workload_grants_status CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text, 'expired'::text])))
);

CREATE TABLE security_audit_events (
    sequence bigint NOT NULL,
    event_id uuid NOT NULL,
    tenant_id text NOT NULL,
    occurred_at_ms bigint NOT NULL,
    actor_kind text NOT NULL,
    actor_principal_id uuid,
    actor_session_id uuid,
    authorization_revision bigint,
    action text NOT NULL,
    outcome text NOT NULL,
    resource_kind text NOT NULL,
    resource_id text,
    request_id text,
    CONSTRAINT security_audit_events_action_shape CHECK ((((octet_length(action) >= 1) AND (octet_length(action) <= 128)) AND (action ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))),
    CONSTRAINT security_audit_events_actor_kind CHECK ((actor_kind = ANY (ARRAY['system'::text, 'human'::text]))),
    CONSTRAINT security_audit_events_actor_shape CHECK (((((actor_kind = 'system'::text) AND (actor_principal_id IS NULL) AND (actor_session_id IS NULL) AND (authorization_revision IS NULL)) OR ((actor_kind = 'human'::text) AND (actor_principal_id IS NOT NULL) AND ((authorization_revision IS NULL) OR (authorization_revision > 0)))) IS TRUE)),
    CONSTRAINT security_audit_events_outcome CHECK ((outcome = ANY (ARRAY['succeeded'::text, 'denied'::text, 'failed'::text]))),
    CONSTRAINT security_audit_events_request_id_shape CHECK (((request_id IS NULL) OR (((octet_length(request_id) >= 1) AND (octet_length(request_id) <= 255)) AND (request_id !~ '[[:space:][:cntrl:]]'::text)))),
    CONSTRAINT security_audit_events_resource_id_shape CHECK (((resource_id IS NULL) OR (((octet_length(resource_id) >= 1) AND (octet_length(resource_id) <= 1024)) AND (resource_id !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT security_audit_events_resource_kind_shape CHECK ((((octet_length(resource_kind) >= 1) AND (octet_length(resource_kind) <= 128)) AND (resource_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)))
);

ALTER TABLE security_audit_events ALTER COLUMN sequence ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME security_audit_events_sequence_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
