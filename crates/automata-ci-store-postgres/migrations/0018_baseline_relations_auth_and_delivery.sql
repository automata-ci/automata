CREATE TABLE installation_state (
    singleton boolean NOT NULL,
    state text NOT NULL,
    configuration_mode text COLLATE pg_catalog."C",
    bootstrap_token_hash bytea,
    bootstrap_hash_key_id text,
    expected_provider_id text,
    expected_provider_subject text,
    challenge_expires_at_ms bigint,
    tenant_id text,
    tenant_display_name text,
    setup_transaction_id uuid,
    configured_tenant_id text,
    configured_principal_id uuid,
    configured_at_ms bigint,
    deployment_authority_sha256 bytea,
    deployment_bootstrap_operation_id uuid,
    deployment_bootstrap_audit_event_id uuid,
    revision bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT installation_state_configuration_mode CHECK (
        configuration_mode IS NULL
        OR configuration_mode IN ('human', 'deployment')
    ),
    CONSTRAINT installation_state_state CHECK (
        state IN ('unconfigured', 'pending', 'configured')
    ),
    CONSTRAINT installation_state_tenant_shape CHECK (
        tenant_id IS NULL
        OR (
            octet_length(tenant_id) BETWEEN 1 AND 255
            AND tenant_id !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT installation_state_tenant_display_name_shape CHECK (
        tenant_display_name IS NULL
        OR (
            octet_length(tenant_display_name) BETWEEN 1 AND 255
            AND NOT (
                ARRAY[
                    ascii(left(tenant_display_name, 1)),
                    ascii(right(tenant_display_name, 1))
                ] && ARRAY[
                    9, 10, 11, 12, 13, 32, 133, 160, 5760,
                    8192, 8193, 8194, 8195, 8196, 8197, 8198,
                    8199, 8200, 8201, 8202, 8232, 8233, 8239,
                    8287, 12288
                ]
            )
            AND tenant_display_name !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT installation_state_deployment_authority_digest CHECK (
        deployment_authority_sha256 IS NULL
        OR (
            octet_length(deployment_authority_sha256) = 32
            AND deployment_authority_sha256 <>
                decode(repeat('00', 32), 'hex')
        )
    ),
    CONSTRAINT installation_state_deployment_ids_non_nil CHECK (
        (
            deployment_bootstrap_operation_id IS NULL
            OR deployment_bootstrap_operation_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
        )
        AND (
            deployment_bootstrap_audit_event_id IS NULL
            OR deployment_bootstrap_audit_event_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
        )
    ),
    CONSTRAINT installation_state_shape CHECK ((
        (
            state = 'unconfigured'
            AND configuration_mode IS NULL
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND expected_provider_id IS NULL
            AND expected_provider_subject IS NULL
            AND challenge_expires_at_ms IS NULL
            AND tenant_id IS NULL
            AND tenant_display_name IS NULL
            AND setup_transaction_id IS NULL
            AND configured_tenant_id IS NULL
            AND configured_principal_id IS NULL
            AND configured_at_ms IS NULL
            AND deployment_authority_sha256 IS NULL
            AND deployment_bootstrap_operation_id IS NULL
            AND deployment_bootstrap_audit_event_id IS NULL
        )
        OR
        (
            state = 'pending'
            AND configuration_mode = 'human'
            AND octet_length(bootstrap_token_hash) = 32
            AND octet_length(bootstrap_hash_key_id) BETWEEN 1 AND 128
            AND bootstrap_hash_key_id ~
                '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_id) BETWEEN 1 AND 128
            AND expected_provider_id ~
                '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_subject) BETWEEN 1 AND 255
            AND expected_provider_subject !~ '[[:cntrl:]]'
            AND challenge_expires_at_ms > updated_at_ms
            AND tenant_id IS NOT NULL
            AND tenant_display_name IS NOT NULL
            AND configured_tenant_id IS NULL
            AND configured_principal_id IS NULL
            AND configured_at_ms IS NULL
            AND deployment_authority_sha256 IS NULL
            AND deployment_bootstrap_operation_id IS NULL
            AND deployment_bootstrap_audit_event_id IS NULL
        )
        OR
        (
            state = 'configured'
            AND configuration_mode = 'human'
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND octet_length(expected_provider_id) BETWEEN 1 AND 128
            AND expected_provider_id ~
                '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_subject) BETWEEN 1 AND 255
            AND expected_provider_subject !~ '[[:cntrl:]]'
            AND challenge_expires_at_ms IS NULL
            AND tenant_id IS NOT NULL
            AND tenant_display_name IS NOT NULL
            AND setup_transaction_id IS NOT NULL
            AND configured_tenant_id = tenant_id
            AND configured_principal_id IS NOT NULL
            AND configured_at_ms >= created_at_ms
            AND deployment_authority_sha256 IS NULL
            AND deployment_bootstrap_operation_id IS NULL
            AND deployment_bootstrap_audit_event_id IS NULL
        )
        OR
        (
            state = 'configured'
            AND configuration_mode = 'deployment'
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND expected_provider_id IS NULL
            AND expected_provider_subject IS NULL
            AND challenge_expires_at_ms IS NULL
            AND tenant_id IS NOT NULL
            AND tenant_display_name IS NOT NULL
            AND setup_transaction_id IS NULL
            AND configured_tenant_id = tenant_id
            AND configured_principal_id IS NULL
            AND configured_at_ms >= created_at_ms
            AND deployment_authority_sha256 IS NOT NULL
            AND deployment_bootstrap_operation_id IS NOT NULL
            AND deployment_bootstrap_audit_event_id IS NOT NULL
        )
    ) IS TRUE),
    CONSTRAINT installation_state_revision_positive CHECK (revision > 0),
    CONSTRAINT installation_state_singleton CHECK (singleton),
    CONSTRAINT installation_state_time_monotonic CHECK (
        updated_at_ms >= created_at_ms
    )
);

CREATE TABLE human_login_transactions (
    id uuid NOT NULL,
    tenant_id text,
    purpose text NOT NULL,
    flow_kind text NOT NULL,
    provider_id text NOT NULL,
    return_path text,
    state_hash bytea,
    state_hash_key_id text,
    browser_binding_hash bytea,
    browser_binding_hash_key_id text,
    poll_proof_hash bytea,
    poll_proof_hash_key_id text,
    encrypted_payload bytea NOT NULL,
    payload_nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    encryption_key_id text NOT NULL,
    encryption_schema integer NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    completed_principal_id uuid,
    poll_interval_ms bigint,
    next_poll_at_ms bigint,
    poll_attempts integer DEFAULT 0 NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    consumed_at_ms bigint,
    revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT human_login_transactions_envelope_shape CHECK ((((octet_length(encrypted_payload) >= 17) AND (octet_length(encrypted_payload) <= 67681)) AND (octet_length(payload_nonce) = 12) AND ((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 65536)) AND ((octet_length(encryption_key_id) >= 1) AND (octet_length(encryption_key_id) <= 128)) AND (encryption_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'::text) AND (encryption_schema = 1))),
    CONSTRAINT human_login_transactions_flow_kind CHECK ((flow_kind = ANY (ARRAY['browser'::text, 'device'::text]))),
    CONSTRAINT human_login_transactions_flow_shape CHECK (((((flow_kind = 'browser'::text) AND (octet_length(state_hash) = 32) AND (state_hash_key_id IS NOT NULL) AND (octet_length(browser_binding_hash) = 32) AND (browser_binding_hash_key_id IS NOT NULL) AND (poll_proof_hash IS NULL) AND (poll_proof_hash_key_id IS NULL) AND (poll_interval_ms IS NULL) AND (next_poll_at_ms IS NULL)) OR ((flow_kind = 'device'::text) AND (state_hash IS NULL) AND (state_hash_key_id IS NULL) AND (browser_binding_hash IS NULL) AND (browser_binding_hash_key_id IS NULL) AND (octet_length(poll_proof_hash) = 32) AND (poll_proof_hash_key_id IS NOT NULL) AND ((poll_interval_ms >= 1000) AND (poll_interval_ms <= 300000)) AND (next_poll_at_ms > created_at_ms))) IS TRUE)),
    CONSTRAINT human_login_transactions_hash_key_shape CHECK ((((state_hash_key_id IS NULL) OR (((octet_length(state_hash_key_id) >= 1) AND (octet_length(state_hash_key_id) <= 128)) AND (state_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))) AND ((browser_binding_hash_key_id IS NULL) OR (((octet_length(browser_binding_hash_key_id) >= 1) AND (octet_length(browser_binding_hash_key_id) <= 128)) AND (browser_binding_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))) AND ((poll_proof_hash_key_id IS NULL) OR (((octet_length(poll_proof_hash_key_id) >= 1) AND (octet_length(poll_proof_hash_key_id) <= 128)) AND (poll_proof_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))))),
    CONSTRAINT human_login_transactions_lifetime CHECK (((updated_at_ms >= created_at_ms) AND (expires_at_ms > created_at_ms) AND ((consumed_at_ms IS NULL) OR (consumed_at_ms <= updated_at_ms)))),
    CONSTRAINT human_login_transactions_poll_attempts_nonnegative CHECK ((poll_attempts >= 0)),
    CONSTRAINT human_login_transactions_provider_shape CHECK ((((octet_length(provider_id) >= 1) AND (octet_length(provider_id) <= 128)) AND (provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))),
    CONSTRAINT human_login_transactions_purpose CHECK ((purpose = ANY (ARRAY['sign_in'::text, 'installation_setup'::text]))),
    CONSTRAINT human_login_transactions_purpose_tenant CHECK (((((purpose = 'sign_in'::text) AND (tenant_id IS NOT NULL)) OR ((purpose = 'installation_setup'::text) AND (tenant_id IS NULL))) IS TRUE)),
    CONSTRAINT human_login_transactions_return_path_shape CHECK (((return_path IS NULL) OR (((octet_length(return_path) >= 1) AND (octet_length(return_path) <= 2048)) AND ("left"(return_path, 1) = '/'::text) AND ("left"(return_path, 2) <> '//'::text) AND (return_path !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT human_login_transactions_revision_positive CHECK ((revision > 0)),
    CONSTRAINT human_login_transactions_status CHECK ((status = ANY (ARRAY['pending'::text, 'consumed'::text, 'succeeded'::text, 'denied'::text, 'expired'::text]))),
    CONSTRAINT human_login_transactions_status_shape CHECK (((((status = 'pending'::text) AND (completed_principal_id IS NULL) AND (consumed_at_ms IS NULL)) OR ((status = 'succeeded'::text) AND (completed_principal_id IS NOT NULL) AND (consumed_at_ms >= created_at_ms)) OR ((status = ANY (ARRAY['consumed'::text, 'denied'::text, 'expired'::text])) AND (completed_principal_id IS NULL) AND (consumed_at_ms >= created_at_ms))) IS TRUE))
);

CREATE TABLE human_principals (
    id uuid NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    display_name text,
    revision bigint DEFAULT 1 NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    disabled_at_ms bigint,
    disabled_reason text,
    CONSTRAINT human_principals_disabled_shape CHECK (((((status = 'active'::text) AND (disabled_at_ms IS NULL) AND (disabled_reason IS NULL)) OR ((status = 'disabled'::text) AND (disabled_at_ms >= created_at_ms) AND ((octet_length(disabled_reason) >= 1) AND (octet_length(disabled_reason) <= 1024)) AND (disabled_reason !~ '[[:cntrl:]]'::text))) IS TRUE)),
    CONSTRAINT human_principals_display_name_shape CHECK (((display_name IS NULL) OR ((octet_length(display_name) <= 1024) AND (display_name !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT human_principals_revision_positive CHECK ((revision > 0)),
    CONSTRAINT human_principals_status CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text]))),
    CONSTRAINT human_principals_time_monotonic CHECK ((updated_at_ms >= created_at_ms))
);

CREATE TABLE human_provider_identities (
    principal_id uuid NOT NULL,
    provider_id text NOT NULL,
    provider_subject text NOT NULL,
    provider_login text NOT NULL,
    normalized_login text NOT NULL,
    display_name text,
    first_authenticated_at_ms bigint NOT NULL,
    last_authenticated_at_ms bigint NOT NULL,
    last_observed_at_ms bigint NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT human_provider_identities_display_name_shape CHECK (((display_name IS NULL) OR ((octet_length(display_name) <= 1024) AND (display_name !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT human_provider_identities_login_shape CHECK ((((octet_length(provider_login) >= 1) AND (octet_length(provider_login) <= 255)) AND (provider_login !~ '[[:cntrl:]]'::text) AND ((octet_length(normalized_login) >= 1) AND (octet_length(normalized_login) <= 255)) AND (normalized_login !~ '[[:cntrl:]]'::text))),
    CONSTRAINT human_provider_identities_provider_shape CHECK ((((octet_length(provider_id) >= 1) AND (octet_length(provider_id) <= 128)) AND (provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))),
    CONSTRAINT human_provider_identities_revision_positive CHECK ((revision > 0)),
    CONSTRAINT human_provider_identities_subject_shape CHECK ((((octet_length(provider_subject) >= 1) AND (octet_length(provider_subject) <= 255)) AND (provider_subject !~ '[[:cntrl:]]'::text))),
    CONSTRAINT human_provider_identities_time_monotonic CHECK (((updated_at_ms >= created_at_ms) AND (last_authenticated_at_ms >= first_authenticated_at_ms) AND (last_observed_at_ms >= first_authenticated_at_ms)))
);

CREATE TABLE human_provider_tokens (
    tenant_id text NOT NULL,
    principal_id uuid NOT NULL,
    provider_id text NOT NULL,
    provider_subject text NOT NULL,
    version bigint NOT NULL,
    grant_kind text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    encrypted_payload bytea,
    payload_nonce bytea,
    wrapped_data_key bytea,
    encryption_key_id text,
    encryption_schema integer,
    issued_at_ms bigint NOT NULL,
    access_expires_at_ms bigint,
    refresh_expires_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    revocation_reason text,
    envelope_record_id uuid NOT NULL,
    token_type text NOT NULL,
    CONSTRAINT human_provider_tokens_envelope_shape CHECK (((((revoked_at_ms IS NULL) AND (revocation_reason IS NULL) AND ((octet_length(encrypted_payload) >= 17) AND (octet_length(encrypted_payload) <= 1048592)) AND (octet_length(payload_nonce) = 12) AND ((octet_length(wrapped_data_key) >= 1) AND (octet_length(wrapped_data_key) <= 65536)) AND ((octet_length(encryption_key_id) >= 1) AND (octet_length(encryption_key_id) <= 64)) AND (encryption_key_id ~ '^[a-z0-9][a-z0-9._-]*$'::text) AND ("right"(encryption_key_id, 1) ~ '^[a-z0-9]$'::text) AND (encryption_schema = 1)) OR ((revoked_at_ms >= issued_at_ms) AND (revocation_reason = ANY (ARRAY['explicit'::text, 'provider_authorization_revoked'::text, 'refresh_rejected'::text, 'principal_disabled'::text, 'provider_identity_unlinked'::text])) AND (encrypted_payload IS NULL) AND (payload_nonce IS NULL) AND (wrapped_data_key IS NULL) AND (encryption_key_id IS NULL) AND (encryption_schema IS NULL))) IS TRUE)),
    CONSTRAINT human_provider_tokens_grant_kind CHECK ((grant_kind = ANY (ARRAY['browser_authorization_code'::text, 'device_authorization'::text]))),
    CONSTRAINT human_provider_tokens_lifetime CHECK (((issued_at_ms >= 0) AND ((access_expires_at_ms IS NULL) OR (access_expires_at_ms > issued_at_ms)) AND ((refresh_expires_at_ms IS NULL) OR (refresh_expires_at_ms > issued_at_ms)) AND (created_at_ms >= 0) AND (updated_at_ms >= created_at_ms))),
    CONSTRAINT human_provider_tokens_scopes_canonical CHECK (automata_provider_token_scopes_are_canonical(scopes)),
    CONSTRAINT human_provider_tokens_token_type_shape CHECK ((((octet_length(token_type) >= 1) AND (octet_length(token_type) <= 255)) AND (token_type ~ '^[!-~]+$'::text))),
    CONSTRAINT human_provider_tokens_version_positive CHECK ((version > 0))
);

CREATE TABLE human_sessions (
    id uuid NOT NULL,
    tenant_id text NOT NULL,
    principal_id uuid NOT NULL,
    provider_id text NOT NULL,
    provider_subject text NOT NULL,
    session_kind text NOT NULL,
    audience text NOT NULL,
    token_hash bytea NOT NULL,
    token_hash_key_id text NOT NULL,
    authorization_revision bigint NOT NULL,
    predecessor_session_id uuid,
    issued_at_ms bigint NOT NULL,
    last_seen_at_ms bigint NOT NULL,
    idle_expires_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    revoked_at_ms bigint,
    revocation_reason text,
    revision bigint DEFAULT 1 NOT NULL,
    lifecycle_status text DEFAULT 'active'::text NOT NULL,
    activation_deadline_ms bigint,
    activated_at_ms bigint,
    CONSTRAINT human_sessions_activation_shape CHECK (((((session_kind = 'browser'::text) AND (audience = 'automata.web'::text) AND (lifecycle_status = 'active'::text) AND (activation_deadline_ms IS NULL) AND (activated_at_ms IS NULL)) OR ((session_kind = 'cli'::text) AND (audience = 'automata.cli'::text) AND (lifecycle_status = 'pending_activation'::text) AND (issued_at_ms >= 0) AND (activation_deadline_ms > issued_at_ms) AND (activation_deadline_ms <= expires_at_ms) AND (((activation_deadline_ms - issued_at_ms) >= 1) AND ((activation_deadline_ms - issued_at_ms) <= 300000)) AND (activated_at_ms IS NULL)) OR ((session_kind = 'cli'::text) AND (audience = 'automata.cli'::text) AND (lifecycle_status = 'active'::text) AND (issued_at_ms >= 0) AND (activation_deadline_ms > issued_at_ms) AND (activation_deadline_ms <= expires_at_ms) AND (((activation_deadline_ms - issued_at_ms) >= 1) AND ((activation_deadline_ms - issued_at_ms) <= 300000)) AND (activated_at_ms >= issued_at_ms) AND (activated_at_ms < activation_deadline_ms))) IS TRUE)),
    CONSTRAINT human_sessions_authorization_revision_positive CHECK ((authorization_revision > 0)),
    CONSTRAINT human_sessions_kind_audience CHECK ((((session_kind = 'browser'::text) AND (audience = 'automata.web'::text)) OR ((session_kind = 'cli'::text) AND (audience = 'automata.cli'::text)))),
    CONSTRAINT human_sessions_lifetime CHECK (((last_seen_at_ms >= issued_at_ms) AND (idle_expires_at_ms > last_seen_at_ms) AND (idle_expires_at_ms <= expires_at_ms) AND (expires_at_ms > issued_at_ms))),
    CONSTRAINT human_sessions_revision_positive CHECK ((revision > 0)),
    CONSTRAINT human_sessions_revocation_shape CHECK (((((revoked_at_ms IS NULL) AND (revocation_reason IS NULL)) OR ((revoked_at_ms >= issued_at_ms) AND ((octet_length(revocation_reason) >= 1) AND (octet_length(revocation_reason) <= 1024)) AND (revocation_reason !~ '[[:cntrl:]]'::text))) IS TRUE)),
    CONSTRAINT human_sessions_token_hash CHECK ((octet_length(token_hash) = 32)),
    CONSTRAINT human_sessions_token_hash_key_shape CHECK ((((octet_length(token_hash_key_id) >= 1) AND (octet_length(token_hash_key_id) <= 128)) AND (token_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)))
);

CREATE TABLE job_attempts (
    id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    lifecycle text NOT NULL,
    fencing_token bigint DEFAULT 0 NOT NULL,
    lease_id uuid,
    runner_id uuid,
    lease_issued_at_ms bigint,
    lease_expires_at_ms bigint,
    lease_failures integer DEFAULT 0 NOT NULL,
    queued_at_ms bigint NOT NULL,
    changed_at_ms bigint NOT NULL,
    runner_session_id uuid,
    runner_session_epoch bigint,
    runner_generation bigint,
    runner_slot integer,
    secret_exposure_class text DEFAULT 'readable_secret'::text NOT NULL,
    raw_log_disposition text DEFAULT 'persist'::text NOT NULL,
    requested_log_visibility text DEFAULT 'private'::text NOT NULL,
    effective_log_visibility text DEFAULT 'private'::text NOT NULL,
    output_safety_reason text DEFAULT 'repository_policy'::text NOT NULL,
    output_safety_schema integer DEFAULT 1 NOT NULL,
    classified_at_ms bigint DEFAULT 0 NOT NULL,
    started_at_ms bigint,
    CONSTRAINT job_attempts_active_lease_consistent CHECK (((lifecycle = ANY (ARRAY['leased'::text, 'preparing'::text, 'running'::text, 'cancelling'::text, 'finalizing'::text])) = (lease_id IS NOT NULL))),
    CONSTRAINT job_attempts_active_lease_fenced CHECK (((lease_id IS NULL) OR (fencing_token > 0))),
    CONSTRAINT job_attempts_active_observation_within_lease CHECK (((lease_id IS NULL) OR (lease_expires_at_ms <= lease_issued_at_ms) OR ((changed_at_ms >= lease_issued_at_ms) AND (changed_at_ms < lease_expires_at_ms)))),
    CONSTRAINT job_attempts_classification_time_nonnegative CHECK ((classified_at_ms >= 0)),
    CONSTRAINT job_attempts_exposure_safety CHECK (((output_safety_schema = 1) AND (raw_log_disposition = 'persist'::text) AND ((secret_exposure_class <> 'readable_secret'::text) OR (effective_log_visibility = 'private'::text)))),
    CONSTRAINT job_attempts_failures_nonnegative CHECK ((lease_failures >= 0)),
    CONSTRAINT job_attempts_fence_nonnegative CHECK ((fencing_token >= 0)),
    CONSTRAINT job_attempts_lease_after_start CHECK (((lease_issued_at_ms IS NULL) OR ((started_at_ms IS NOT NULL) AND (lease_issued_at_ms >= started_at_ms)))),
    CONSTRAINT job_attempts_lease_fields_consistent CHECK ((((lease_id IS NULL) AND (runner_id IS NULL) AND (lease_issued_at_ms IS NULL) AND (lease_expires_at_ms IS NULL) AND (runner_session_id IS NULL) AND (runner_session_epoch IS NULL) AND (runner_generation IS NULL) AND (runner_slot IS NULL)) OR ((lease_id IS NOT NULL) AND (runner_id IS NOT NULL) AND (lease_issued_at_ms IS NOT NULL) AND (lease_expires_at_ms IS NOT NULL) AND (runner_session_id IS NOT NULL) AND (runner_session_epoch IS NOT NULL) AND (runner_generation IS NOT NULL) AND (runner_slot IS NOT NULL)))),
    CONSTRAINT job_attempts_lease_interval CHECK (((lease_id IS NULL) OR (lease_expires_at_ms > lease_issued_at_ms))),
    CONSTRAINT job_attempts_lifecycle CHECK ((lifecycle = ANY (ARRAY['queued'::text, 'leased'::text, 'preparing'::text, 'running'::text, 'cancelling'::text, 'finalizing'::text, 'succeeded'::text, 'failed'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text, 'lost'::text]))),
    CONSTRAINT job_attempts_log_visibility CHECK (((requested_log_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text])) AND (effective_log_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text])))),
    CONSTRAINT job_attempts_log_visibility_cap CHECK (((effective_log_visibility = 'private'::text) OR ((effective_log_visibility = 'authenticated'::text) AND (requested_log_visibility = ANY (ARRAY['authenticated'::text, 'public'::text]))) OR ((effective_log_visibility = 'public'::text) AND (requested_log_visibility = 'public'::text)))),
    CONSTRAINT job_attempts_number_positive CHECK ((attempt_number > 0)),
    CONSTRAINT job_attempts_output_safety_reason_code CHECK ((output_safety_reason = ANY (ARRAY['repository_policy'::text, 'secret_exposure'::text]))),
    CONSTRAINT job_attempts_output_safety_schema CHECK ((output_safety_schema = 1)),
    CONSTRAINT job_attempts_raw_log_disposition CHECK ((raw_log_disposition = 'persist'::text)),
    CONSTRAINT job_attempts_runner_generation_positive CHECK (((runner_generation IS NULL) OR (runner_generation > 0))),
    CONSTRAINT job_attempts_runner_slot_range CHECK (((runner_slot IS NULL) OR ((runner_slot >= 1) AND (runner_slot <= 65535)))),
    CONSTRAINT job_attempts_secret_exposure_class CHECK ((secret_exposure_class = ANY (ARRAY['secretless'::text, 'capability_only'::text, 'readable_secret'::text]))),
    CONSTRAINT job_attempts_session_epoch_positive CHECK (((runner_session_epoch IS NULL) OR (runner_session_epoch > 0))),
    CONSTRAINT job_attempts_started_at_shape CHECK (((started_at_ms IS NULL) OR ((started_at_ms >= 0) AND (started_at_ms <= changed_at_ms)))),
    CONSTRAINT job_attempts_state_time_monotonic CHECK ((changed_at_ms >= queued_at_ms))
);

CREATE TABLE job_dependencies (
    run_id uuid NOT NULL,
    job_id uuid NOT NULL,
    prerequisite_job_id uuid NOT NULL,
    CONSTRAINT job_dependencies_no_self_edge CHECK ((job_id <> prerequisite_job_id))
);

CREATE TABLE job_missing_secret_bindings (
    attempt_id uuid NOT NULL,
    canonical_name text NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT job_missing_secret_bindings_created_at CHECK ((created_at_ms >= 0)),
    CONSTRAINT job_missing_secret_bindings_name CHECK (((canonical_name ~ '^[A-Z_][A-Z0-9_]*$'::text) AND (octet_length(canonical_name) <= 255)))
);

CREATE TABLE job_missing_variable_bindings (
    attempt_id uuid NOT NULL,
    canonical_name text NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT job_missing_variable_bindings_created_at CHECK ((created_at_ms >= 0)),
    CONSTRAINT job_missing_variable_bindings_name CHECK (((canonical_name ~ '^[A-Z_][A-Z0-9_]*$'::text) AND (octet_length(canonical_name) <= 255)))
);

CREATE TABLE job_secret_bindings (
    attempt_id uuid NOT NULL,
    canonical_name text NOT NULL,
    tenant_id text NOT NULL,
    grant_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    binding_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT job_secret_bindings_created_at CHECK ((created_at_ms >= 0)),
    CONSTRAINT job_secret_bindings_digest CHECK ((octet_length(binding_digest) = 32)),
    CONSTRAINT job_secret_bindings_fence CHECK (((fencing_token > 0) AND (lease_id <> '00000000-0000-0000-0000-000000000000'::uuid)))
);

CREATE TABLE job_secret_selections (
    attempt_id uuid NOT NULL,
    canonical_name text NOT NULL,
    tenant_id text NOT NULL,
    secret_id uuid NOT NULL,
    secret_version_id uuid NOT NULL,
    secret_version_number bigint NOT NULL,
    scope_kind text NOT NULL,
    environment_id uuid,
    binding_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT job_secret_selections_created_at CHECK ((created_at_ms >= 0)),
    CONSTRAINT job_secret_selections_digest CHECK ((octet_length(binding_digest) = 32)),
    CONSTRAINT job_secret_selections_environment_shape CHECK (((scope_kind = 'environment'::text) = (environment_id IS NOT NULL))),
    CONSTRAINT job_secret_selections_name CHECK (((canonical_name ~ '^[A-Z_][A-Z0-9_]*$'::text) AND (octet_length(canonical_name) <= 255))),
    CONSTRAINT job_secret_selections_scope CHECK ((scope_kind = ANY (ARRAY['tenant'::text, 'repository'::text, 'environment'::text])))
);

CREATE TABLE job_variable_bindings (
    attempt_id uuid NOT NULL,
    canonical_name text NOT NULL,
    tenant_id text NOT NULL,
    variable_id uuid NOT NULL,
    variable_version_id uuid NOT NULL,
    variable_version_number bigint NOT NULL,
    scope_kind text NOT NULL,
    environment_id uuid,
    binding_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT job_variable_bindings_created_at CHECK ((created_at_ms >= 0)),
    CONSTRAINT job_variable_bindings_digest CHECK ((octet_length(binding_digest) = 32)),
    CONSTRAINT job_variable_bindings_name CHECK (((canonical_name ~ '^[A-Z_][A-Z0-9_]*$'::text) AND (octet_length(canonical_name) <= 255))),
    CONSTRAINT job_variable_bindings_scope CHECK ((((scope_kind = 'repository'::text) AND (environment_id IS NULL)) OR ((scope_kind = 'environment'::text) AND (environment_id IS NOT NULL))))
);

CREATE TABLE jobs (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    job_key text NOT NULL,
    display_name text NOT NULL,
    job_ir_digest bytea NOT NULL,
    job_ir_object_key text NOT NULL,
    requirements jsonb NOT NULL,
    created_at_ms bigint NOT NULL,
    admission_epoch integer NOT NULL,
    job_ir_schema integer NOT NULL,
    job_ir_size_bytes bigint NOT NULL,
    CONSTRAINT jobs_admission_epoch_exact CHECK ((admission_epoch = 1)),
    CONSTRAINT jobs_current_admission_metadata CHECK (((admission_epoch = 1) AND (job_ir_schema = 1) AND ((job_ir_size_bytes >= 1) AND (job_ir_size_bytes <= 16777216)) AND (requirements @> '{"schema_version": 1}'::jsonb) AND (requirements ? 'resource_allocation'::text))),
    CONSTRAINT jobs_ir_object_key_nonempty CHECK ((length(job_ir_object_key) > 0)),
    CONSTRAINT jobs_ir_sha256 CHECK ((octet_length(job_ir_digest) = 32)),
    CONSTRAINT jobs_key_nonempty CHECK ((length(job_key) > 0))
);

CREATE TABLE managed_secret_delivery_operations (
    tenant_id text NOT NULL,
    operation_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    run_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_id uuid NOT NULL,
    runner_session_epoch bigint CONSTRAINT managed_secret_delivery_operation_runner_session_epoch_not_null NOT NULL,
    runner_generation bigint NOT NULL,
    runner_slot smallint NOT NULL,
    runtime_context_digest bytea CONSTRAINT managed_secret_delivery_operati_runtime_context_digest_not_null NOT NULL,
    binding_set_digest bytea NOT NULL,
    authority_evidence_schema smallint DEFAULT 1 NOT NULL,
    authority_evidence_digest bytea CONSTRAINT managed_secret_delivery_oper_authority_evidence_digest_not_null NOT NULL,
    credential_key_id text NOT NULL,
    credential_sha256 bytea NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    created_at_ms bigint NOT NULL,
    usable_until_ms bigint NOT NULL,
    acknowledged_at_ms bigint,
    CONSTRAINT managed_secret_delivery_operations_authority_schema CHECK ((authority_evidence_schema = 1)),
    CONSTRAINT managed_secret_delivery_operations_digests CHECK (((octet_length(runtime_context_digest) = 32) AND (octet_length(binding_set_digest) = 32) AND (octet_length(authority_evidence_digest) = 32) AND (octet_length(credential_sha256) = 32))),
    CONSTRAINT managed_secret_delivery_operations_fences_positive CHECK (((fencing_token > 0) AND (runner_session_epoch > 0) AND (runner_generation > 0) AND (runner_slot > 0))),
    CONSTRAINT managed_secret_delivery_operations_key_shape CHECK ((((octet_length(credential_key_id) >= 1) AND (octet_length(credential_key_id) <= 128)) AND (credential_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))),
    CONSTRAINT managed_secret_delivery_operations_lifetime CHECK (((created_at_ms >= 0) AND (usable_until_ms > created_at_ms))),
    CONSTRAINT managed_secret_delivery_operations_state CHECK ((state = ANY (ARRAY['pending'::text, 'acknowledged'::text, 'expired'::text]))),
    CONSTRAINT managed_secret_delivery_operations_state_shape CHECK (((((state = 'pending'::text) AND (acknowledged_at_ms IS NULL)) OR ((state = 'acknowledged'::text) AND (acknowledged_at_ms >= created_at_ms) AND (acknowledged_at_ms < usable_until_ms)) OR ((state = 'expired'::text) AND (acknowledged_at_ms IS NULL))) IS TRUE))
);

CREATE TABLE protected_environment_approval_decisions (
    tenant_id text NOT NULL,
    request_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    decision text NOT NULL,
    reason text,
    decided_at_ms bigint NOT NULL,
    CONSTRAINT protected_environment_approval_decisions_decision CHECK ((decision = ANY (ARRAY['approve'::text, 'reject'::text]))),
    CONSTRAINT protected_environment_approval_decisions_reason_code CHECK (((reason IS NULL) OR (reason = ANY (ARRAY['policy_reviewed'::text, 'change_reviewed'::text, 'security_reviewed'::text, 'administrative_review'::text]))))
);

CREATE TABLE protected_environment_approval_requests (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    run_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    id uuid NOT NULL,
    required_approvals smallint CONSTRAINT protected_environment_approval_requ_required_approvals_not_null NOT NULL,
    prevent_self_review boolean CONSTRAINT protected_environment_approval_req_prevent_self_review_not_null NOT NULL,
    requested_by_principal_id uuid,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    resolved_at_ms bigint,
    resolution_reason text,
    revision bigint DEFAULT 1 NOT NULL,
    environment_revision bigint CONSTRAINT protected_environment_approval_re_environment_revision_not_null NOT NULL,
    CONSTRAINT protected_environment_approval_environment_revision_positive CHECK ((environment_revision > 0)),
    CONSTRAINT protected_environment_approval_requester_required CHECK (((status <> 'approved'::text) OR (NOT prevent_self_review) OR (requested_by_principal_id IS NOT NULL))),
    CONSTRAINT protected_environment_approval_requests_lifetime CHECK ((expires_at_ms > created_at_ms)),
    CONSTRAINT protected_environment_approval_requests_required_count CHECK (((required_approvals >= 1) AND (required_approvals <= 25))),
    CONSTRAINT protected_environment_approval_requests_revision_positive CHECK ((revision > 0)),
    CONSTRAINT protected_environment_approval_requests_status CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'expired'::text, 'cancelled'::text]))),
    CONSTRAINT protected_environment_approval_requests_status_shape CHECK (((((status = 'pending'::text) AND (resolved_at_ms IS NULL) AND (resolution_reason IS NULL)) OR ((status = 'approved'::text) AND (resolved_at_ms >= created_at_ms) AND (resolution_reason = ANY (ARRAY['approval_threshold_met'::text, 'administrative_approval'::text]))) OR ((status = 'rejected'::text) AND (resolved_at_ms >= created_at_ms) AND (resolution_reason = ANY (ARRAY['approval_rejected'::text, 'administrative_rejection'::text]))) OR ((status = 'expired'::text) AND (resolved_at_ms >= created_at_ms) AND (resolution_reason = 'approval_expired'::text)) OR ((status = 'cancelled'::text) AND (resolved_at_ms >= created_at_ms) AND (resolution_reason = ANY (ARRAY['workload_cancelled'::text, 'environment_disabled'::text, 'policy_changed'::text])))) IS TRUE))
);

CREATE TABLE provider_delivery_inbox (
    id uuid NOT NULL,
    tenant_id text NOT NULL,
    provider text NOT NULL COLLATE pg_catalog."C",
    connection_id uuid NOT NULL,
    installation_id bigint NOT NULL,
    provider_repository_id bigint NOT NULL,
    repository_visibility text NOT NULL COLLATE pg_catalog."C",
    repository_identity text NOT NULL COLLATE pg_catalog."C",
    delivery_id text NOT NULL COLLATE pg_catalog."C",
    request_digest bytea NOT NULL,
    raw_event_digest bytea NOT NULL,
    raw_event_object_key text NOT NULL COLLATE pg_catalog."C",
    raw_event_size_bytes bigint NOT NULL,
    raw_event_media_type text NOT NULL COLLATE pg_catalog."C",
    state text DEFAULT 'pending'::text NOT NULL,
    attempt_count smallint DEFAULT 0 NOT NULL,
    claim_fence bigint DEFAULT 0 NOT NULL,
    claim_owner_id uuid,
    claimed_at_ms bigint,
    claim_expires_at_ms bigint,
    renewal_predecessor_expires_at_ms bigint,
    next_attempt_at_ms bigint,
    last_failure_kind text COLLATE pg_catalog."C",
    terminal_claim_owner_id uuid,
    terminal_claim_fence bigint,
    completion_digest bytea,
    completion_outcome_count smallint,
    completed_at_ms bigint,
    rejected_at_ms bigint,
    accepted_at_ms bigint NOT NULL,
    state_updated_at_ms bigint NOT NULL,
    CONSTRAINT provider_delivery_inbox_attempt_bound CHECK (((attempt_count >= 0) AND (attempt_count <= 16))),
    CONSTRAINT provider_delivery_inbox_claim_owner_non_nil CHECK (((claim_owner_id IS NULL) OR (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT provider_delivery_inbox_connection_non_nil CHECK ((connection_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT provider_delivery_inbox_delivery_id_shape CHECK ((((octet_length(delivery_id) >= 1) AND (octet_length(delivery_id) <= 255)) AND (btrim(delivery_id) = delivery_id) AND (delivery_id !~ '[[:cntrl:]]'::text))),
    CONSTRAINT provider_delivery_inbox_failure_kind_shape CHECK (((last_failure_kind IS NULL) OR (((octet_length(last_failure_kind) >= 1) AND (octet_length(last_failure_kind) <= 128)) AND (last_failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)))),
    CONSTRAINT provider_delivery_inbox_fence_nonnegative CHECK ((claim_fence >= 0)),
    CONSTRAINT provider_delivery_inbox_id_non_nil CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT provider_delivery_inbox_numeric_authority_positive CHECK (((installation_id > 0) AND (provider_repository_id > 0))),
    CONSTRAINT provider_delivery_inbox_provider_shape CHECK ((((octet_length(provider) >= 1) AND (octet_length(provider) <= 128)) AND (provider ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text))),
    CONSTRAINT provider_delivery_inbox_raw_event_sha256 CHECK ((octet_length(raw_event_digest) = 32)),
    CONSTRAINT provider_delivery_inbox_raw_media_type_shape CHECK ((((octet_length(raw_event_media_type) >= 3) AND (octet_length(raw_event_media_type) <= 128)) AND (raw_event_media_type ~~ '%/%'::text) AND (raw_event_media_type !~ '[[:space:][:cntrl:];]'::text))),
    CONSTRAINT provider_delivery_inbox_raw_object_key_shape CHECK ((((octet_length(raw_event_object_key) >= 1) AND (octet_length(raw_event_object_key) <= 1024)) AND (raw_event_object_key !~ '[[:cntrl:]]'::text) AND ("left"(raw_event_object_key, 1) <> '/'::text) AND (raw_event_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT provider_delivery_inbox_raw_size_bounded CHECK (((raw_event_size_bytes >= 1) AND (raw_event_size_bytes <= 26214400))),
    CONSTRAINT provider_delivery_inbox_repository_identity_shape CHECK ((((octet_length(repository_identity) >= 1) AND (octet_length(repository_identity) <= 1024)) AND (btrim(repository_identity) = repository_identity) AND (repository_identity !~ '[[:cntrl:]]'::text))),
    CONSTRAINT provider_delivery_inbox_repository_visibility CHECK ((repository_visibility = ANY (ARRAY['public'::text, 'private'::text]))),
    CONSTRAINT provider_delivery_inbox_request_sha256 CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT provider_delivery_inbox_state CHECK ((state = ANY (ARRAY['pending'::text, 'claimed'::text, 'retry'::text, 'completed'::text, 'rejected'::text]))),
    CONSTRAINT provider_delivery_inbox_state_shape CHECK (((((state = 'pending'::text) AND (attempt_count = 0) AND (claim_fence = 0) AND (claim_owner_id IS NULL) AND (claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL) AND (renewal_predecessor_expires_at_ms IS NULL) AND (next_attempt_at_ms IS NULL) AND (last_failure_kind IS NULL) AND (terminal_claim_owner_id IS NULL) AND (terminal_claim_fence IS NULL) AND (completion_digest IS NULL) AND (completion_outcome_count IS NULL) AND (completed_at_ms IS NULL) AND (rejected_at_ms IS NULL) AND (state_updated_at_ms = accepted_at_ms)) OR ((state = 'claimed'::text) AND ((attempt_count >= 1) AND (attempt_count <= 16)) AND (claim_fence > 0) AND (claim_owner_id IS NOT NULL) AND (claimed_at_ms >= accepted_at_ms) AND (state_updated_at_ms >= claimed_at_ms) AND (claim_expires_at_ms > state_updated_at_ms) AND ((claim_expires_at_ms - state_updated_at_ms) <= 900000) AND ((claim_expires_at_ms - claimed_at_ms) <= 3600000) AND (((state_updated_at_ms = claimed_at_ms) AND (renewal_predecessor_expires_at_ms IS NULL)) OR ((state_updated_at_ms > claimed_at_ms) AND (renewal_predecessor_expires_at_ms > state_updated_at_ms) AND (renewal_predecessor_expires_at_ms < claim_expires_at_ms))) AND (next_attempt_at_ms IS NULL) AND (terminal_claim_owner_id IS NULL) AND (terminal_claim_fence IS NULL) AND (completion_digest IS NULL) AND (completion_outcome_count IS NULL) AND (completed_at_ms IS NULL) AND (rejected_at_ms IS NULL)) OR ((state = 'retry'::text) AND ((attempt_count >= 1) AND (attempt_count <= 15)) AND (claim_fence > 0) AND (claim_owner_id IS NULL) AND (claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL) AND (renewal_predecessor_expires_at_ms IS NULL) AND (next_attempt_at_ms > state_updated_at_ms) AND ((next_attempt_at_ms - state_updated_at_ms) <= 86400000) AND (last_failure_kind IS NOT NULL) AND (terminal_claim_owner_id IS NULL) AND (terminal_claim_fence IS NULL) AND (completion_digest IS NULL) AND (completion_outcome_count IS NULL) AND (completed_at_ms IS NULL) AND (rejected_at_ms IS NULL)) OR ((state = 'completed'::text) AND ((attempt_count >= 1) AND (attempt_count <= 16)) AND (claim_fence > 0) AND (claim_owner_id IS NULL) AND (claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL) AND (renewal_predecessor_expires_at_ms IS NULL) AND (next_attempt_at_ms IS NULL) AND (terminal_claim_owner_id IS NOT NULL) AND (terminal_claim_fence = claim_fence) AND (octet_length(completion_digest) = 32) AND ((completion_outcome_count >= 0) AND (completion_outcome_count <= 256)) AND (completed_at_ms = state_updated_at_ms) AND (rejected_at_ms IS NULL)) OR ((state = 'rejected'::text) AND ((attempt_count >= 1) AND (attempt_count <= 16)) AND (claim_fence > 0) AND (claim_owner_id IS NULL) AND (claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL) AND (renewal_predecessor_expires_at_ms IS NULL) AND (next_attempt_at_ms IS NULL) AND (last_failure_kind IS NOT NULL) AND (terminal_claim_owner_id IS NOT NULL) AND (terminal_claim_fence = claim_fence) AND (completion_digest IS NULL) AND (completion_outcome_count IS NULL) AND (completed_at_ms IS NULL) AND (rejected_at_ms = state_updated_at_ms))) IS TRUE)),
    CONSTRAINT provider_delivery_inbox_terminal_owner_non_nil CHECK (((terminal_claim_owner_id IS NULL) OR (terminal_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT provider_delivery_inbox_time_monotonic CHECK (((accepted_at_ms >= 0) AND (state_updated_at_ms >= accepted_at_ms)))
);

CREATE TABLE provider_delivery_workflow_inventories (
    inbox_id uuid NOT NULL,
    tenant_id text NOT NULL,
    manifest_digest bytea NOT NULL,
    source_revision text NOT NULL COLLATE pg_catalog."C",
    repository_source_digest bytea CONSTRAINT provider_delivery_workflow_in_repository_source_digest_not_null NOT NULL,
    inventory_digest bytea CONSTRAINT provider_delivery_workflow_inventorie_inventory_digest_not_null NOT NULL,
    workflow_count smallint NOT NULL,
    registered_at_ms bigint CONSTRAINT provider_delivery_workflow_inventorie_registered_at_ms_not_null NOT NULL,
    CONSTRAINT provider_delivery_workflow_inventories_shape CHECK (((octet_length(manifest_digest) = 32) AND (octet_length(repository_source_digest) = 32) AND (octet_length(inventory_digest) = 32) AND ((octet_length(source_revision) >= 1) AND (octet_length(source_revision) <= 1024)) AND (btrim(source_revision) = source_revision) AND (source_revision !~ '[[:cntrl:]]'::text) AND ((workflow_count >= 0) AND (workflow_count <= 256)) AND (registered_at_ms >= 0)))
);

CREATE TABLE provider_delivery_workflow_inventory_entries (
    inbox_id uuid NOT NULL,
    tenant_id text NOT NULL,
    ordinal smallint NOT NULL,
    workflow_path text CONSTRAINT provider_delivery_workflow_inventory_ent_workflow_path_not_null NOT NULL COLLATE pg_catalog."C",
    source_state text CONSTRAINT provider_delivery_workflow_inventory_entr_source_state_not_null NOT NULL COLLATE pg_catalog."C",
    source_digest bytea,
    CONSTRAINT provider_delivery_workflow_inventory_entries_shape CHECK ((((ordinal >= 0) AND (ordinal <= 255)) AND (workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'::text) AND (workflow_path !~ '[[:cntrl:]\\]'::text) AND (((source_state = 'ready'::text) AND (octet_length(source_digest) = 32)) OR ((source_state = ANY (ARRAY['empty'::text, 'oversized'::text, 'missing'::text])) AND (source_digest IS NULL)))))
);

CREATE TABLE provider_delivery_workflow_outcomes (
    inbox_id uuid NOT NULL,
    tenant_id text NOT NULL,
    ordinal smallint NOT NULL,
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    outcome_kind text NOT NULL,
    repository_id uuid,
    run_id uuid,
    failure_kind text COLLATE pg_catalog."C",
    created_at_ms bigint NOT NULL,
    CONSTRAINT provider_delivery_workflow_outcomes_failure_shape CHECK (((failure_kind IS NULL) OR (((octet_length(failure_kind) >= 1) AND (octet_length(failure_kind) <= 128)) AND (failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'::text)))),
    CONSTRAINT provider_delivery_workflow_outcomes_kind CHECK ((outcome_kind = ANY (ARRAY['admitted'::text, 'skipped'::text, 'failed'::text]))),
    CONSTRAINT provider_delivery_workflow_outcomes_ordinal_bound CHECK (((ordinal >= 0) AND (ordinal <= 255))),
    CONSTRAINT provider_delivery_workflow_outcomes_path_shape CHECK ((((octet_length(workflow_path) >= 1) AND (octet_length(workflow_path) <= 1024)) AND (btrim(workflow_path) = workflow_path) AND (workflow_path !~ '[[:cntrl:]\\]'::text) AND ("left"(workflow_path, 1) <> '/'::text) AND (workflow_path !~ '(^|/)(\.|\.\.)(/|$)'::text) AND (workflow_path !~ '//'::text))),
    CONSTRAINT provider_delivery_workflow_outcomes_shape CHECK (((((outcome_kind = 'admitted'::text) AND (repository_id IS NOT NULL) AND (run_id IS NOT NULL) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (failure_kind IS NULL)) OR ((outcome_kind = ANY (ARRAY['skipped'::text, 'failed'::text])) AND (repository_id IS NULL) AND (run_id IS NULL) AND (failure_kind IS NOT NULL))) IS TRUE)),
    CONSTRAINT provider_delivery_workflow_outcomes_time_nonnegative CHECK ((created_at_ms >= 0))
);

CREATE TABLE provider_delivery_workflow_progress (
    inbox_id uuid NOT NULL,
    tenant_id text NOT NULL,
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    inventory_digest bytea NOT NULL,
    outcome_kind text NOT NULL COLLATE pg_catalog."C",
    run_id uuid,
    failure_kind text COLLATE pg_catalog."C",
    recorded_at_ms bigint NOT NULL,
    CONSTRAINT provider_delivery_workflow_progress_shape CHECK (((octet_length(inventory_digest) = 32) AND (recorded_at_ms >= 0) AND (((outcome_kind = 'admitted'::text) AND (run_id IS NOT NULL) AND (failure_kind IS NULL)) OR ((outcome_kind = ANY (ARRAY['skipped'::text, 'failed'::text])) AND (run_id IS NULL) AND ((octet_length(failure_kind) >= 1) AND (octet_length(failure_kind) <= 128)) AND (failure_kind ~ '^[a-z0-9](?:[a-z0-9_.:-]*[a-z0-9])?$|^[a-z0-9]$'::text)))))
);
