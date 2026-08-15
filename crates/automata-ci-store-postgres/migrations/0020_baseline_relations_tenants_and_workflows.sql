CREATE TABLE tenant_human_memberships (
    tenant_id text NOT NULL,
    principal_id uuid NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    authorization_revision bigint DEFAULT 1 NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    suspended_at_ms bigint,
    suspended_reason text,
    CONSTRAINT tenant_human_memberships_authorization_revision_positive CHECK ((authorization_revision > 0)),
    CONSTRAINT tenant_human_memberships_revision_positive CHECK ((revision > 0)),
    CONSTRAINT tenant_human_memberships_status CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text]))),
    CONSTRAINT tenant_human_memberships_suspension_shape CHECK (((((status = 'active'::text) AND (suspended_at_ms IS NULL) AND (suspended_reason IS NULL)) OR ((status = 'suspended'::text) AND (suspended_at_ms >= created_at_ms) AND ((octet_length(suspended_reason) >= 1) AND (octet_length(suspended_reason) <= 1024)) AND (suspended_reason !~ '[[:cntrl:]]'::text))) IS TRUE)),
    CONSTRAINT tenant_human_memberships_time_monotonic CHECK ((updated_at_ms >= created_at_ms))
);

CREATE TABLE tenants (
    id text NOT NULL,
    display_name text NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    login_admission_mode text DEFAULT 'restricted'::text NOT NULL,
    authorization_revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT tenants_authorization_revision_positive CHECK ((authorization_revision > 0)),
    CONSTRAINT tenants_display_name_nonempty CHECK ((length(display_name) > 0)),
    CONSTRAINT tenants_id_shape CHECK ((((octet_length(id) >= 1) AND (octet_length(id) <= 255)) AND (id !~ '[[:cntrl:]]'::text))),
    CONSTRAINT tenants_login_admission_mode CHECK ((login_admission_mode = ANY (ARRAY['restricted'::text, 'open_sign_in'::text])))
);

CREATE TABLE workspace_provisioning_operations (
    authority_id text NOT NULL,
    operation_id uuid NOT NULL,
    shard_id text NOT NULL,
    workspace_id text NOT NULL,
    workspace_display_name text NOT NULL,
    initial_owner_issuer text NOT NULL,
    initial_owner_subject uuid NOT NULL,
    initial_owner_display_name text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    initial_owner_principal_id uuid,
    created_at_ms bigint NOT NULL,
    provisioned_at_ms bigint,
    CONSTRAINT workspace_provisioning_operations_authority_shape CHECK ((((octet_length(authority_id) >= 1) AND (octet_length(authority_id) <= 255)) AND (authority_id !~ '[[:space:][:cntrl:]]'::text))),
    CONSTRAINT workspace_provisioning_operations_display_name_shape CHECK (((char_length(workspace_display_name) >= 1) AND (char_length(workspace_display_name) <= 255) AND (btrim(workspace_display_name) = workspace_display_name) AND (workspace_display_name !~ '[[:cntrl:]]'::text) AND (char_length(initial_owner_display_name) >= 1) AND (char_length(initial_owner_display_name) <= 255) AND (btrim(initial_owner_display_name) = initial_owner_display_name) AND (initial_owner_display_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT workspace_provisioning_operations_ids_non_nil CHECK (((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (initial_owner_subject <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((initial_owner_principal_id IS NULL) OR (initial_owner_principal_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT workspace_provisioning_operations_issuer_shape CHECK ((((octet_length(initial_owner_issuer) >= 9) AND (octet_length(initial_owner_issuer) <= 2048)) AND (initial_owner_issuer ~ '^https://'::text) AND (initial_owner_issuer !~ '[[:cntrl:][:space:]]'::text))),
    CONSTRAINT workspace_provisioning_operations_shard_shape CHECK ((((octet_length(shard_id) >= 1) AND (octet_length(shard_id) <= 63)) AND (shard_id ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'::text))),
    CONSTRAINT workspace_provisioning_operations_state CHECK ((state = ANY (ARRAY['pending'::text, 'completed'::text]))),
    CONSTRAINT workspace_provisioning_operations_state_shape CHECK (((((state = 'pending'::text) AND (initial_owner_principal_id IS NULL) AND (provisioned_at_ms IS NULL)) OR ((state = 'completed'::text) AND (initial_owner_principal_id IS NOT NULL) AND (provisioned_at_ms >= created_at_ms))) IS TRUE)),
    CONSTRAINT workspace_provisioning_operations_time_nonnegative CHECK ((created_at_ms >= 0)),
    CONSTRAINT workspace_provisioning_operations_workspace_shape CHECK ((((octet_length(workspace_id) = 36) AND (workspace_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text))))
);

CREATE TABLE workspace_management_bindings (
    workspace_id text PRIMARY KEY,
    authority_id text NOT NULL,
    shard_id text NOT NULL,
    created_at_ms bigint NOT NULL,
    CONSTRAINT workspace_management_bindings_authority_shape CHECK ((((octet_length(authority_id) >= 1) AND (octet_length(authority_id) <= 255)) AND (authority_id !~ '[[:space:][:cntrl:]]'::text))),
    CONSTRAINT workspace_management_bindings_shard_shape CHECK ((((octet_length(shard_id) >= 1) AND (octet_length(shard_id) <= 63)) AND (shard_id ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'::text))),
    CONSTRAINT workspace_management_bindings_time_nonnegative CHECK ((created_at_ms >= 0)),
    CONSTRAINT workspace_management_bindings_exact_authority UNIQUE (workspace_id, authority_id, shard_id)
);

CREATE TABLE workspace_entitlement_operations (
    authority_id text NOT NULL,
    operation_id uuid NOT NULL,
    shard_id text NOT NULL,
    workspace_id text NOT NULL,
    revision bigint NOT NULL,
    policy_kind text NOT NULL,
    compute_limit_ms bigint,
    valid_for_ms bigint,
    applied_at_ms bigint NOT NULL,
    expires_at_ms bigint,
    CONSTRAINT workspace_entitlement_operations_pkey PRIMARY KEY (authority_id, operation_id),
    CONSTRAINT workspace_entitlement_operations_exact_revision UNIQUE (authority_id, operation_id, workspace_id, revision),
    CONSTRAINT workspace_entitlement_operations_workspace_revision_unique UNIQUE (workspace_id, revision),
    CONSTRAINT workspace_entitlement_operations_binding FOREIGN KEY (workspace_id, authority_id, shard_id) REFERENCES workspace_management_bindings(workspace_id, authority_id, shard_id) ON DELETE RESTRICT,
    CONSTRAINT workspace_entitlement_operations_ids_non_nil CHECK ((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT workspace_entitlement_operations_revision_positive CHECK ((revision > 0)),
    CONSTRAINT workspace_entitlement_operations_policy CHECK ((policy_kind = ANY (ARRAY['capped'::text, 'uncapped'::text, 'paused'::text]))),
    CONSTRAINT workspace_entitlement_operations_policy_shape CHECK (((((policy_kind = 'capped'::text) AND (compute_limit_ms > 0)) OR ((policy_kind = ANY (ARRAY['uncapped'::text, 'paused'::text])) AND (compute_limit_ms IS NULL) AND (valid_for_ms IS NULL) AND (expires_at_ms IS NULL))) IS TRUE)),
    CONSTRAINT workspace_entitlement_operations_validity_shape CHECK (((((valid_for_ms IS NULL) AND (expires_at_ms IS NULL)) OR ((valid_for_ms > 0) AND (expires_at_ms = applied_at_ms + valid_for_ms))) IS TRUE)),
    CONSTRAINT workspace_entitlement_operations_time_nonnegative CHECK ((applied_at_ms >= 0))
);

CREATE TABLE workspace_execution_entitlements (
    workspace_id text PRIMARY KEY,
    authority_id text NOT NULL,
    shard_id text NOT NULL,
    revision bigint NOT NULL,
    operation_id uuid NOT NULL,
    policy_kind text NOT NULL,
    compute_limit_ms bigint,
    valid_for_ms bigint,
    consumed_compute_ms bigint DEFAULT 0 NOT NULL,
    state text NOT NULL,
    applied_at_ms bigint NOT NULL,
    expires_at_ms bigint,
    exhausted_at_ms bigint,
    CONSTRAINT workspace_execution_entitlements_binding FOREIGN KEY (workspace_id, authority_id, shard_id) REFERENCES workspace_management_bindings(workspace_id, authority_id, shard_id) ON DELETE RESTRICT,
    CONSTRAINT workspace_execution_entitlements_operation FOREIGN KEY (authority_id, operation_id, workspace_id, revision) REFERENCES workspace_entitlement_operations(authority_id, operation_id, workspace_id, revision) ON DELETE RESTRICT,
    CONSTRAINT workspace_execution_entitlements_revision_positive CHECK ((revision > 0)),
    CONSTRAINT workspace_execution_entitlements_compute_nonnegative CHECK ((consumed_compute_ms >= 0)),
    CONSTRAINT workspace_execution_entitlements_policy CHECK ((policy_kind = ANY (ARRAY['capped'::text, 'uncapped'::text, 'paused'::text]))),
    CONSTRAINT workspace_execution_entitlements_policy_shape CHECK (((((policy_kind = 'capped'::text) AND (compute_limit_ms > 0)) OR ((policy_kind = ANY (ARRAY['uncapped'::text, 'paused'::text])) AND (compute_limit_ms IS NULL) AND (valid_for_ms IS NULL) AND (expires_at_ms IS NULL))) IS TRUE)),
    CONSTRAINT workspace_execution_entitlements_validity_shape CHECK (((((valid_for_ms IS NULL) AND (expires_at_ms IS NULL)) OR ((valid_for_ms > 0) AND (expires_at_ms = applied_at_ms + valid_for_ms))) IS TRUE)),
    CONSTRAINT workspace_execution_entitlements_state CHECK ((state = ANY (ARRAY['active'::text, 'paused'::text, 'exhausted'::text]))),
    CONSTRAINT workspace_execution_entitlements_state_shape CHECK (((((state = 'active'::text) AND (policy_kind <> 'paused'::text) AND (exhausted_at_ms IS NULL)) OR ((state = 'paused'::text) AND (policy_kind = 'paused'::text) AND (consumed_compute_ms = 0) AND (exhausted_at_ms IS NULL)) OR ((state = 'exhausted'::text) AND (policy_kind = 'capped'::text) AND (exhausted_at_ms >= applied_at_ms))) IS TRUE)),
    CONSTRAINT workspace_execution_entitlements_time_nonnegative CHECK ((applied_at_ms >= 0))
);

CREATE TABLE workflow_admission_receipts (
    tenant_id text NOT NULL,
    idempotency_kind text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    repository_id uuid,
    run_id uuid,
    committed_at_ms bigint,
    github_subject_evidence_required boolean DEFAULT false CONSTRAINT workflow_admission_receipts_github_subject_evidence_re_not_null NOT NULL,
    CONSTRAINT workflow_admission_receipts_completion_shape CHECK ((((repository_id IS NULL) AND (run_id IS NULL) AND (committed_at_ms IS NULL)) OR ((repository_id IS NOT NULL) AND (run_id IS NOT NULL) AND (committed_at_ms IS NOT NULL)))),
    CONSTRAINT workflow_admission_receipts_key_shape CHECK ((((octet_length(idempotency_key) >= 1) AND (octet_length(idempotency_key) <= 1024)) AND (idempotency_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT workflow_admission_receipts_kind CHECK ((idempotency_kind = ANY (ARRAY['provider_delivery'::text, 'operation'::text]))),
    CONSTRAINT workflow_admission_receipts_sha256 CHECK ((octet_length(request_digest) = 32))
);

CREATE TABLE workflow_artifact_block_commits (
    artifact_id bigint NOT NULL,
    list_digest bytea NOT NULL,
    block_ids text[] NOT NULL,
    size_bytes bigint NOT NULL,
    committed_at_seconds bigint NOT NULL,
    CONSTRAINT workflow_artifact_commits_count CHECK ((((cardinality(block_ids) >= 0) AND (cardinality(block_ids) <= 100000)) AND (array_position(block_ids, NULL::text) IS NULL))),
    CONSTRAINT workflow_artifact_commits_digest CHECK ((octet_length(list_digest) = 32)),
    CONSTRAINT workflow_artifact_commits_size CHECK ((size_bytes >= 0))
);

CREATE TABLE workflow_artifact_blocks (
    artifact_id bigint NOT NULL,
    block_id text NOT NULL,
    object_key text NOT NULL,
    digest bytea NOT NULL,
    size_bytes bigint NOT NULL,
    media_type text NOT NULL,
    staged_at_seconds bigint NOT NULL,
    state text DEFAULT 'ready'::text NOT NULL,
    ready_at_seconds bigint,
    CONSTRAINT workflow_artifact_blocks_digest CHECK ((octet_length(digest) = 32)),
    CONSTRAINT workflow_artifact_blocks_id_shape CHECK ((((octet_length(block_id) >= 4) AND (octet_length(block_id) <= 128)) AND (block_id !~ '[[:space:][:cntrl:]]'::text))),
    CONSTRAINT workflow_artifact_blocks_key_shape CHECK ((((octet_length(object_key) >= 1) AND (octet_length(object_key) <= 1024)) AND (object_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT workflow_artifact_blocks_media_type CHECK ((((octet_length(media_type) >= 3) AND (octet_length(media_type) <= 128)) AND (media_type !~ '[[:space:][:cntrl:];]'::text))),
    CONSTRAINT workflow_artifact_blocks_readiness CHECK (((((state = 'reserved'::text) AND (ready_at_seconds IS NULL)) OR ((state = 'ready'::text) AND (ready_at_seconds >= staged_at_seconds))) IS TRUE)),
    CONSTRAINT workflow_artifact_blocks_size CHECK (((size_bytes >= 0) AND (size_bytes <= '4294967296'::bigint))),
    CONSTRAINT workflow_artifact_blocks_state CHECK ((state = ANY (ARRAY['reserved'::text, 'ready'::text])))
);

CREATE TABLE workflow_artifacts (
    id bigint NOT NULL,
    upload_id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    run_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    name text NOT NULL,
    protocol_version integer NOT NULL,
    mime_type text NOT NULL,
    expires_at_seconds bigint,
    block_id_encoded_length integer,
    state text DEFAULT 'pending'::text NOT NULL,
    content_digest bytea,
    content_size_bytes bigint,
    manifest_object_key text,
    manifest_digest bytea,
    manifest_size_bytes bigint,
    manifest_media_type text,
    created_at_seconds bigint NOT NULL,
    finalized_at_seconds bigint,
    manifest_state text,
    manifest_reserved_at_seconds bigint,
    secret_exposure_class text DEFAULT 'readable_secret'::text NOT NULL,
    requested_visibility text DEFAULT 'private'::text NOT NULL,
    effective_visibility text DEFAULT 'private'::text NOT NULL,
    publication_safety_reason text DEFAULT 'repository_policy'::text NOT NULL,
    publication_safety_schema integer DEFAULT 1 NOT NULL,
    finalization_generation bigint DEFAULT 0 NOT NULL,
    finalization_claimed_size_bytes bigint,
    finalization_claimed_digest bytea,
    finalization_claim_expires_at_seconds bigint,
    manifest_bytes bytea,
    CONSTRAINT workflow_artifacts_block_id_length CHECK (((block_id_encoded_length IS NULL) OR ((block_id_encoded_length >= 4) AND (block_id_encoded_length <= 128)))),
    CONSTRAINT workflow_artifacts_expiry_positive CHECK (((expires_at_seconds IS NULL) OR (expires_at_seconds > created_at_seconds))),
    CONSTRAINT workflow_artifacts_exposure_safety CHECK (((secret_exposure_class <> 'readable_secret'::text) OR (effective_visibility = 'private'::text))),
    CONSTRAINT workflow_artifacts_fence_positive CHECK ((fencing_token > 0)),
    CONSTRAINT workflow_artifacts_finalization_claim CHECK (((((finalization_generation = 0) AND (finalization_claimed_size_bytes IS NULL) AND (finalization_claimed_digest IS NULL) AND (finalization_claim_expires_at_seconds IS NULL)) OR ((finalization_generation > 0) AND (finalization_claimed_size_bytes >= 0) AND ((finalization_claimed_digest IS NULL) OR (octet_length(finalization_claimed_digest) = 32)) AND (finalization_claim_expires_at_seconds >= created_at_seconds))) IS TRUE)),
    CONSTRAINT workflow_artifacts_manifest_state CHECK (((manifest_state IS NULL) OR (manifest_state = ANY (ARRAY['reserved'::text, 'ready'::text])))),
    CONSTRAINT workflow_artifacts_mime_type_shape CHECK ((((octet_length(mime_type) >= 3) AND (octet_length(mime_type) <= 128)) AND (mime_type !~ '[[:space:][:cntrl:];]'::text))),
    CONSTRAINT workflow_artifacts_name_shape CHECK ((((octet_length(name) >= 1) AND (octet_length(name) <= 255)) AND (name !~ '[[:cntrl:]"/:<>|*?\\]'::text))),
    CONSTRAINT workflow_artifacts_protocol_version CHECK ((protocol_version = 1)),
    CONSTRAINT workflow_artifacts_publication_safety_reason_code CHECK ((publication_safety_reason = ANY (ARRAY['repository_policy'::text, 'secret_exposure'::text]))),
    CONSTRAINT workflow_artifacts_publication_safety_schema CHECK ((publication_safety_schema = 1)),
    CONSTRAINT workflow_artifacts_publication_shape CHECK (((((state = 'pending'::text) AND (manifest_state IS NULL) AND (content_digest IS NULL) AND (content_size_bytes IS NULL) AND (manifest_object_key IS NULL) AND (manifest_digest IS NULL) AND (manifest_size_bytes IS NULL) AND (manifest_media_type IS NULL) AND (manifest_bytes IS NULL) AND (manifest_reserved_at_seconds IS NULL) AND (finalized_at_seconds IS NULL)) OR ((state = 'pending'::text) AND (manifest_state = 'reserved'::text) AND (finalization_generation > 0) AND (finalization_claimed_size_bytes = content_size_bytes) AND ((finalization_claimed_digest IS NULL) OR (finalization_claimed_digest = content_digest)) AND (octet_length(content_digest) = 32) AND (content_size_bytes >= 0) AND ((octet_length(manifest_object_key) >= 1) AND (octet_length(manifest_object_key) <= 1024)) AND (manifest_object_key !~ '[[:cntrl:]]'::text) AND (octet_length(manifest_digest) = 32) AND ((manifest_size_bytes >= 1) AND (manifest_size_bytes <= 1048576)) AND (octet_length(manifest_bytes) = manifest_size_bytes) AND ((octet_length(manifest_media_type) >= 3) AND (octet_length(manifest_media_type) <= 128)) AND (manifest_media_type !~ '[[:space:][:cntrl:];]'::text) AND (manifest_reserved_at_seconds >= created_at_seconds) AND (finalized_at_seconds IS NULL)) OR ((state = 'finalized'::text) AND (manifest_state = 'ready'::text) AND (finalization_generation > 0) AND (finalization_claimed_size_bytes = content_size_bytes) AND ((finalization_claimed_digest IS NULL) OR (finalization_claimed_digest = content_digest)) AND (octet_length(content_digest) = 32) AND (content_size_bytes >= 0) AND ((octet_length(manifest_object_key) >= 1) AND (octet_length(manifest_object_key) <= 1024)) AND (manifest_object_key !~ '[[:cntrl:]]'::text) AND (octet_length(manifest_digest) = 32) AND ((manifest_size_bytes >= 1) AND (manifest_size_bytes <= 1048576)) AND (octet_length(manifest_bytes) = manifest_size_bytes) AND ((octet_length(manifest_media_type) >= 3) AND (octet_length(manifest_media_type) <= 128)) AND (manifest_media_type !~ '[[:space:][:cntrl:];]'::text) AND (manifest_reserved_at_seconds >= created_at_seconds) AND (finalized_at_seconds >= manifest_reserved_at_seconds))) IS TRUE)),
    CONSTRAINT workflow_artifacts_secret_exposure_class CHECK ((secret_exposure_class = ANY (ARRAY['secretless'::text, 'capability_only'::text, 'readable_secret'::text]))),
    CONSTRAINT workflow_artifacts_state CHECK ((state = ANY (ARRAY['pending'::text, 'finalized'::text]))),
    CONSTRAINT workflow_artifacts_visibility CHECK (((requested_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text])) AND (effective_visibility = ANY (ARRAY['private'::text, 'authenticated'::text, 'public'::text])))),
    CONSTRAINT workflow_artifacts_visibility_cap CHECK (((effective_visibility = 'private'::text) OR ((effective_visibility = 'authenticated'::text) AND (requested_visibility = ANY (ARRAY['authenticated'::text, 'public'::text]))) OR ((effective_visibility = 'public'::text) AND (requested_visibility = 'public'::text))))
);

ALTER TABLE workflow_artifacts ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME workflow_artifacts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE workflow_definitions (
    id uuid NOT NULL,
    repository_id uuid NOT NULL,
    path text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT workflow_definitions_path_nonempty CHECK ((length(path) > 0))
);

CREATE TABLE logical_workflow_activation_preparation_claims (
    logical_job_id uuid CONSTRAINT logical_workflow_activation_preparation_logical_job_id_not_null NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_activation_preparation__invocation_id_not_null NOT NULL,
    descriptor_digest bytea CONSTRAINT logical_workflow_activation_preparat_descriptor_digest_not_null NOT NULL,
    logical_key text CONSTRAINT logical_workflow_activation_preparation_cl_logical_key_not_null NOT NULL COLLATE pg_catalog."C",
    source_order integer CONSTRAINT logical_workflow_activation_preparation_c_source_order_not_null NOT NULL,
    workflow_id uuid CONSTRAINT logical_workflow_activation_preparation_cl_workflow_id_not_null NOT NULL,
    workflow_name text CONSTRAINT logical_workflow_activation_preparation__workflow_name_not_null NOT NULL COLLATE pg_catalog."C",
    git_ref text NOT NULL COLLATE pg_catalog."C",
    actor text COLLATE pg_catalog."C",
    run_number bigint CONSTRAINT logical_workflow_activation_preparation_cla_run_number_not_null NOT NULL,
    run_attempt integer CONSTRAINT logical_workflow_activation_preparation_cl_run_attempt_not_null NOT NULL,
    plan_digest bytea CONSTRAINT logical_workflow_activation_preparation_cl_plan_digest_not_null NOT NULL,
    plan_object_key text CONSTRAINT logical_workflow_activation_preparatio_plan_object_key_not_null NOT NULL COLLATE pg_catalog."C",
    plan_size_bytes bigint CONSTRAINT logical_workflow_activation_preparatio_plan_size_bytes_not_null NOT NULL,
    plan_media_type text CONSTRAINT logical_workflow_activation_preparatio_plan_media_type_not_null NOT NULL COLLATE pg_catalog."C",
    plan_schema smallint CONSTRAINT logical_workflow_activation_preparation_cl_plan_schema_not_null NOT NULL,
    event_digest bytea CONSTRAINT logical_workflow_activation_preparation_c_event_digest_not_null NOT NULL,
    event_object_key text CONSTRAINT logical_workflow_activation_preparati_event_object_key_not_null NOT NULL COLLATE pg_catalog."C",
    event_size_bytes bigint CONSTRAINT logical_workflow_activation_preparati_event_size_bytes_not_null NOT NULL,
    event_media_type text CONSTRAINT logical_workflow_activation_preparati_event_media_type_not_null NOT NULL COLLATE pg_catalog."C",
    base_context_kind text CONSTRAINT logical_workflow_activation_preparat_base_context_kind_not_null NOT NULL,
    workspace text CONSTRAINT logical_workflow_activation_preparation_clai_workspace_not_null NOT NULL COLLATE pg_catalog."C",
    prerequisite_count integer CONSTRAINT logical_workflow_activation_prepara_prerequisite_count_not_null NOT NULL,
    prerequisites_digest bytea CONSTRAINT logical_workflow_activation_prepa_prerequisites_digest_not_null NOT NULL,
    aggregate_status text CONSTRAINT logical_workflow_activation_preparati_aggregate_status_not_null NOT NULL,
    evidence_ready_at_ms bigint CONSTRAINT logical_workflow_activation_prepa_evidence_ready_at_ms_not_null NOT NULL,
    state text NOT NULL,
    owner_id uuid CONSTRAINT logical_workflow_activation_preparation_claim_owner_id_not_null NOT NULL,
    generation bigint CONSTRAINT logical_workflow_activation_preparation_cla_generation_not_null NOT NULL,
    claimed_at_ms bigint CONSTRAINT logical_workflow_activation_preparation__claimed_at_ms_not_null NOT NULL,
    expires_at_ms bigint CONSTRAINT logical_workflow_activation_preparation__expires_at_ms_not_null NOT NULL,
    created_at_ms bigint CONSTRAINT logical_workflow_activation_preparation__created_at_ms_not_null NOT NULL,
    updated_at_ms bigint CONSTRAINT logical_workflow_activation_preparation__updated_at_ms_not_null NOT NULL,
    authority_profile text CONSTRAINT logical_workflow_activation_preparat_authority_profile_not_null NOT NULL COLLATE pg_catalog."C",
    runtime_policy_revision bigint CONSTRAINT logical_workflow_activation_pr_runtime_policy_revision_not_null NOT NULL,
    runtime_policy_digest bytea CONSTRAINT logical_workflow_activation_prep_runtime_policy_digest_not_null NOT NULL,
    runner_policy_digest bytea CONSTRAINT logical_workflow_activation_prepa_runner_policy_digest_not_null NOT NULL,
    runner_policy_object_key text CONSTRAINT logical_workflow_activation_p_runner_policy_object_key_not_null NOT NULL COLLATE pg_catalog."C",
    runner_policy_size_bytes bigint CONSTRAINT logical_workflow_activation_p_runner_policy_size_bytes_not_null NOT NULL,
    runner_policy_media_type text CONSTRAINT logical_workflow_activation_p_runner_policy_media_type_not_null NOT NULL COLLATE pg_catalog."C",
    origin_selection_id uuid,
    base_context_digest bytea,
    base_context_object_key text COLLATE pg_catalog."C",
    base_context_size_bytes bigint,
    base_context_media_type text COLLATE pg_catalog."C",
    base_context_schema smallint,
    CONSTRAINT logical_workflow_activation_preparation_claims_authority CHECK ((automata_is_canonical_logical_activation_workspace(workspace) AND (((base_context_kind = 'root_empty'::text) AND (base_context_digest IS NULL) AND (base_context_object_key IS NULL) AND (base_context_size_bytes IS NULL) AND (base_context_media_type IS NULL) AND (base_context_schema IS NULL)) OR ((base_context_kind = 'admission'::text) AND (base_context_digest IS NOT NULL) AND (base_context_object_key IS NOT NULL) AND (base_context_size_bytes IS NOT NULL) AND (base_context_media_type IS NOT NULL) AND (base_context_schema IS NOT NULL) AND (octet_length(base_context_digest) = 32) AND ((octet_length(base_context_object_key) >= 1) AND (octet_length(base_context_object_key) <= 1024)) AND (base_context_object_key !~ '[[:cntrl:]]'::text) AND ("left"(base_context_object_key, 1) <> '/'::text) AND (base_context_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((base_context_size_bytes >= 1) AND (base_context_size_bytes <= 16777216)) AND (base_context_media_type = 'application/vnd.automata.job-runtime-context.protobuf'::text) AND (base_context_schema = 1))))),
    CONSTRAINT logical_workflow_activation_preparation_claims_authority_profil CHECK ((authority_profile = ANY (ARRAY['standard'::text, 'credential_free'::text]))),
    CONSTRAINT logical_workflow_activation_preparation_claims_digests CHECK (((octet_length(descriptor_digest) = 32) AND (octet_length(plan_digest) = 32) AND (octet_length(event_digest) = 32) AND (octet_length(prerequisites_digest) = 32))),
    CONSTRAINT logical_workflow_activation_preparation_claims_event CHECK ((((octet_length(event_object_key) >= 1) AND (octet_length(event_object_key) <= 1024)) AND (event_object_key !~ '[[:cntrl:]]'::text) AND ("left"(event_object_key, 1) <> '/'::text) AND (event_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((event_size_bytes >= 1) AND (event_size_bytes <= 26214400)) AND (event_media_type = 'application/json'::text))),
    CONSTRAINT logical_workflow_activation_preparation_claims_evidence CHECK ((((prerequisite_count >= 0) AND (prerequisite_count <= 128)) AND (aggregate_status = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'skipped'::text])) AND (evidence_ready_at_ms >= 0))),
    CONSTRAINT logical_workflow_activation_preparation_claims_execution CHECK ((((octet_length(workflow_name) >= 1) AND (octet_length(workflow_name) <= 1024)) AND (workflow_name !~ '[[:cntrl:]]'::text) AND ((octet_length(git_ref) >= 6) AND (octet_length(git_ref) <= 1024)) AND (git_ref ~~ 'refs/%'::text) AND (git_ref !~ '[[:cntrl:]]'::text) AND ((actor IS NULL) OR (((octet_length(actor) >= 1) AND (octet_length(actor) <= 1024)) AND (actor !~ '[[:cntrl:]]'::text))) AND (run_number > 0) AND (run_attempt > 0))),
    CONSTRAINT logical_workflow_activation_preparation_claims_fence CHECK (((generation > 0) AND (claimed_at_ms >= evidence_ready_at_ms) AND (expires_at_ms > claimed_at_ms) AND ((expires_at_ms - claimed_at_ms) <= 900000) AND (created_at_ms <= claimed_at_ms) AND (updated_at_ms >= claimed_at_ms))),
    CONSTRAINT logical_workflow_activation_preparation_claims_ids CHECK (((logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_activation_preparation_claims_key CHECK ((((octet_length(logical_key) >= 1) AND (octet_length(logical_key) <= 256)) AND (btrim(logical_key) = logical_key) AND (logical_key !~ '[[:cntrl:]]'::text) AND ((source_order >= 0) AND (source_order <= 1023)))),
    CONSTRAINT logical_workflow_activation_preparation_claims_plan CHECK ((((octet_length(plan_object_key) >= 1) AND (octet_length(plan_object_key) <= 1024)) AND (plan_object_key !~ '[[:cntrl:]]'::text) AND ("left"(plan_object_key, 1) <> '/'::text) AND (plan_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((plan_size_bytes >= 1) AND (plan_size_bytes <= 16777216)) AND (plan_media_type = 'application/vnd.automata.workflow-plan+json'::text) AND (plan_schema = 1))),
    CONSTRAINT logical_workflow_activation_preparation_claims_state CHECK ((state = ANY (ARRAY['preparing'::text, 'prepared'::text]))),
    CONSTRAINT logical_workflow_preparation_claims_runtime_policy CHECK (((runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32))),
    CONSTRAINT logical_workflow_preparation_runner_policy_shape CHECK (((octet_length(runner_policy_digest) = 32) AND (runner_policy_object_key = (('github/runner-policy/v1/'::text || encode(runner_policy_digest, 'hex'::text)) || '.json'::text)) AND ((runner_policy_size_bytes >= 1) AND (runner_policy_size_bytes <= 65536)) AND (runner_policy_media_type = 'application/vnd.automata.github-runner-policy+json'::text) AND ((origin_selection_id IS NULL) OR (origin_selection_id <> '00000000-0000-0000-0000-000000000000'::uuid))))
);

CREATE TABLE logical_workflow_activation_preparation_outputs (
    logical_job_id uuid CONSTRAINT logical_workflow_activation_preparatio_logical_job_id_not_null2 NOT NULL,
    prerequisite_job_id uuid CONSTRAINT logical_workflow_activation_prepa_prerequisite_job_id_not_null1 NOT NULL,
    output_name text CONSTRAINT logical_workflow_activation_preparation_ou_output_name_not_null NOT NULL COLLATE pg_catalog."C",
    sensitivity text CONSTRAINT logical_workflow_activation_preparation_ou_sensitivity_not_null NOT NULL,
    public_value text,
    CONSTRAINT logical_workflow_activation_preparation_outputs_shape CHECK ((((octet_length(output_name) >= 1) AND (octet_length(output_name) <= 256)) AND (btrim(output_name) = output_name) AND (output_name !~ '[[:cntrl:]]'::text) AND (((sensitivity = 'public'::text) AND (public_value IS NOT NULL) AND (octet_length(public_value) <= 2097152)) OR ((sensitivity = 'secret_derived'::text) AND (public_value IS NULL)))))
);

CREATE TABLE logical_workflow_activation_preparation_prerequisites (
    logical_job_id uuid CONSTRAINT logical_workflow_activation_preparatio_logical_job_id_not_null1 NOT NULL,
    prerequisite_job_id uuid CONSTRAINT logical_workflow_activation_prepar_prerequisite_job_id_not_null NOT NULL,
    logical_key text CONSTRAINT logical_workflow_activation_preparation_pr_logical_key_not_null NOT NULL COLLATE pg_catalog."C",
    source_order integer CONSTRAINT logical_workflow_activation_preparation_p_source_order_not_null NOT NULL,
    result_descriptor_digest bytea CONSTRAINT logical_workflow_activation_p_result_descriptor_digest_not_null NOT NULL,
    outputs_digest bytea CONSTRAINT logical_workflow_activation_preparation_outputs_digest_not_null NOT NULL,
    commit_digest bytea CONSTRAINT logical_workflow_activation_preparation__commit_digest_not_null NOT NULL,
    effective_conclusion text CONSTRAINT logical_workflow_activation_prepa_effective_conclusion_not_null NOT NULL,
    closure_has_failure boolean CONSTRAINT logical_workflow_activation_prepar_closure_has_failure_not_null NOT NULL,
    closure_has_cancelled boolean CONSTRAINT logical_workflow_activation_prep_closure_has_cancelled_not_null NOT NULL,
    closure_has_skipped boolean CONSTRAINT logical_workflow_activation_prepar_closure_has_skipped_not_null NOT NULL,
    output_count integer CONSTRAINT logical_workflow_activation_preparation_p_output_count_not_null NOT NULL,
    finalized_at_ms bigint CONSTRAINT logical_workflow_activation_preparatio_finalized_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_activation_preparation_prerequisites_shape CHECK (((prerequisite_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((octet_length(logical_key) >= 1) AND (octet_length(logical_key) <= 256)) AND (btrim(logical_key) = logical_key) AND (logical_key !~ '[[:cntrl:]]'::text) AND ((source_order >= 0) AND (source_order <= 1023)) AND (octet_length(result_descriptor_digest) = 32) AND (octet_length(outputs_digest) = 32) AND (octet_length(commit_digest) = 32) AND (effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text])) AND ((output_count >= 0) AND (output_count <= 256)) AND (finalized_at_ms >= 0) AND ((effective_conclusion <> ALL (ARRAY['failure'::text, 'timed_out'::text])) OR closure_has_failure) AND ((effective_conclusion <> 'cancelled'::text) OR closure_has_cancelled) AND ((effective_conclusion <> 'skipped'::text) OR closure_has_skipped)))
);

CREATE TABLE logical_workflow_activation_preparations (
    logical_job_id uuid CONSTRAINT logical_workflow_activation_preparatio_logical_job_id_not_null3 NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    descriptor_digest bytea CONSTRAINT logical_workflow_activation_prepara_descriptor_digest_not_null1 NOT NULL,
    base_context_digest bytea CONSTRAINT logical_workflow_activation_prepar_base_context_digest_not_null NOT NULL,
    base_context_object_key text CONSTRAINT logical_workflow_activation_pr_base_context_object_key_not_null NOT NULL COLLATE pg_catalog."C",
    base_context_size_bytes bigint CONSTRAINT logical_workflow_activation_pr_base_context_size_bytes_not_null NOT NULL,
    base_context_media_type text CONSTRAINT logical_workflow_activation_pr_base_context_media_type_not_null NOT NULL COLLATE pg_catalog."C",
    base_context_schema smallint CONSTRAINT logical_workflow_activation_prepar_base_context_schema_not_null NOT NULL,
    prerequisite_context_digest bytea CONSTRAINT logical_workflow_activation_prerequisite_context_diges_not_null NOT NULL,
    prerequisite_context_object_key text CONSTRAINT logical_workflow_activation_prerequisite_context_objec_not_null NOT NULL COLLATE pg_catalog."C",
    prerequisite_context_size_bytes bigint CONSTRAINT logical_workflow_activation_prerequisite_context_size__not_null NOT NULL,
    prerequisite_context_media_type text CONSTRAINT logical_workflow_activation_prerequisite_context_media_not_null NOT NULL COLLATE pg_catalog."C",
    prerequisite_context_schema smallint CONSTRAINT logical_workflow_activation_prerequisite_context_schem_not_null NOT NULL,
    activation_input_digest bytea CONSTRAINT logical_workflow_activation_pr_activation_input_digest_not_null NOT NULL,
    claim_owner_id uuid CONSTRAINT logical_workflow_activation_preparatio_claim_owner_id_not_null1 NOT NULL,
    claim_generation bigint CONSTRAINT logical_workflow_activation_preparati_claim_generation_not_null NOT NULL,
    claim_started_at_ms bigint CONSTRAINT logical_workflow_activation_prepar_claim_started_at_ms_not_null NOT NULL,
    claim_expires_at_ms bigint CONSTRAINT logical_workflow_activation_prepar_claim_expires_at_ms_not_null NOT NULL,
    bound_at_ms bigint NOT NULL,
    authority_profile text CONSTRAINT logical_workflow_activation_prepara_authority_profile_not_null1 NOT NULL COLLATE pg_catalog."C",
    runtime_policy_revision bigint CONSTRAINT logical_workflow_activation_p_runtime_policy_revision_not_null1 NOT NULL,
    runtime_policy_digest bytea CONSTRAINT logical_workflow_activation_pre_runtime_policy_digest_not_null1 NOT NULL,
    claim_origin_selection_id uuid CONSTRAINT logical_workflow_activation__claim_origin_selection_id_not_null NOT NULL,
    CONSTRAINT logical_workflow_activation_preparations_authority_profile CHECK ((authority_profile = ANY (ARRAY['standard'::text, 'credential_free'::text]))),
    CONSTRAINT logical_workflow_activation_preparations_contexts CHECK (((base_context_object_key <> prerequisite_context_object_key) AND ((octet_length(base_context_object_key) >= 1) AND (octet_length(base_context_object_key) <= 1024)) AND (base_context_object_key !~ '[[:cntrl:]]'::text) AND ("left"(base_context_object_key, 1) <> '/'::text) AND (base_context_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((base_context_size_bytes >= 1) AND (base_context_size_bytes <= 16777216)) AND (base_context_media_type = 'application/vnd.automata.job-runtime-context.protobuf'::text) AND (base_context_schema = 1) AND ((octet_length(prerequisite_context_object_key) >= 1) AND (octet_length(prerequisite_context_object_key) <= 1024)) AND (prerequisite_context_object_key !~ '[[:cntrl:]]'::text) AND ("left"(prerequisite_context_object_key, 1) <> '/'::text) AND (prerequisite_context_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((prerequisite_context_size_bytes >= 1) AND (prerequisite_context_size_bytes <= 16777216)) AND (prerequisite_context_media_type = 'application/vnd.automata.job-runtime-context.protobuf'::text) AND (prerequisite_context_schema = 1))),
    CONSTRAINT logical_workflow_activation_preparations_digests CHECK (((octet_length(descriptor_digest) = 32) AND (octet_length(base_context_digest) = 32) AND (octet_length(prerequisite_context_digest) = 32) AND (octet_length(activation_input_digest) = 32))),
    CONSTRAINT logical_workflow_activation_preparations_fence CHECK (((claim_generation > 0) AND (claim_started_at_ms >= 0) AND (claim_expires_at_ms > claim_started_at_ms) AND ((claim_expires_at_ms - claim_started_at_ms) <= 900000) AND (bound_at_ms >= claim_started_at_ms) AND (bound_at_ms < claim_expires_at_ms))),
    CONSTRAINT logical_workflow_activation_preparations_ids CHECK (((logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_preparations_runtime_policy CHECK (((runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32))),
    CONSTRAINT logical_workflow_preparations_selection_origin CHECK ((claim_origin_selection_id <> '00000000-0000-0000-0000-000000000000'::uuid))
);

CREATE TABLE logical_workflow_activation_publications (
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid CONSTRAINT logical_workflow_activation_publication_logical_job_id_not_null NOT NULL,
    activation_input_digest bytea CONSTRAINT logical_workflow_activation_pu_activation_input_digest_not_null NOT NULL,
    activation_output_digest bytea CONSTRAINT logical_workflow_activation_p_activation_output_digest_not_null NOT NULL,
    activation_owner_id uuid CONSTRAINT logical_workflow_activation_public_activation_owner_id_not_null NOT NULL,
    activation_generation bigint CONSTRAINT logical_workflow_activation_publ_activation_generation_not_null NOT NULL,
    activation_claimed_at_ms bigint CONSTRAINT logical_workflow_activation_p_activation_claimed_at_ms_not_null NOT NULL,
    activation_expires_at_ms bigint CONSTRAINT logical_workflow_activation_p_activation_expires_at_ms_not_null NOT NULL,
    condition_matched boolean CONSTRAINT logical_workflow_activation_publicat_condition_matched_not_null NOT NULL,
    instance_count integer CONSTRAINT logical_workflow_activation_publication_instance_count_not_null NOT NULL,
    job_ir_version smallint CONSTRAINT logical_workflow_activation_publication_job_ir_version_not_null NOT NULL,
    runtime_context_schema smallint CONSTRAINT logical_workflow_activation_pub_runtime_context_schema_not_null NOT NULL,
    published_at_ms bigint CONSTRAINT logical_workflow_activation_publicatio_published_at_ms_not_null NOT NULL,
    authority_profile text CONSTRAINT logical_workflow_activation_publicat_authority_profile_not_null NOT NULL COLLATE pg_catalog."C",
    runtime_policy_revision bigint CONSTRAINT logical_workflow_activation_pu_runtime_policy_revision_not_null NOT NULL,
    runtime_policy_digest bytea CONSTRAINT logical_workflow_activation_publ_runtime_policy_digest_not_null NOT NULL,
    CONSTRAINT logical_workflow_activation_publications_authority_profile CHECK ((authority_profile = ANY (ARRAY['standard'::text, 'credential_free'::text]))),
    CONSTRAINT logical_workflow_activation_publications_claim_interval CHECK (((activation_claimed_at_ms >= 0) AND (activation_expires_at_ms > activation_claimed_at_ms) AND ((activation_expires_at_ms - activation_claimed_at_ms) <= 900000) AND (published_at_ms >= activation_claimed_at_ms) AND (published_at_ms < activation_expires_at_ms))),
    CONSTRAINT logical_workflow_activation_publications_condition_shape CHECK ((condition_matched OR (instance_count = 0))),
    CONSTRAINT logical_workflow_activation_publications_context_exact CHECK ((runtime_context_schema = 1)),
    CONSTRAINT logical_workflow_activation_publications_generation_positive CHECK ((activation_generation > 0)),
    CONSTRAINT logical_workflow_activation_publications_input_sha256 CHECK ((octet_length(activation_input_digest) = 32)),
    CONSTRAINT logical_workflow_activation_publications_instance_bound CHECK (((instance_count >= 0) AND (instance_count <= 256))),
    CONSTRAINT logical_workflow_activation_publications_job_ir_exact CHECK ((job_ir_version = 1)),
    CONSTRAINT logical_workflow_activation_publications_output_sha256 CHECK ((octet_length(activation_output_digest) = 32)),
    CONSTRAINT logical_workflow_activation_publications_owner_non_nil CHECK ((activation_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_activation_publications_time_nonnegative CHECK ((published_at_ms >= 0)),
    CONSTRAINT logical_workflow_publications_runtime_policy CHECK (((runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32)))
);

CREATE TABLE logical_workflow_activation_renewal_receipts (
    logical_job_id uuid CONSTRAINT logical_workflow_activation_renewal_rec_logical_job_id_not_null NOT NULL,
    authority_kind text CONSTRAINT logical_workflow_activation_renewal_rec_authority_kind_not_null NOT NULL,
    selection_id uuid CONSTRAINT logical_workflow_activation_renewal_recei_selection_id_not_null NOT NULL,
    tenant_id text NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_activation_renewal_rece_invocation_id_not_null NOT NULL,
    owner_id uuid NOT NULL,
    runtime_policy_revision bigint CONSTRAINT logical_workflow_activation_re_runtime_policy_revision_not_null NOT NULL,
    runtime_policy_digest bytea CONSTRAINT logical_workflow_activation_rene_runtime_policy_digest_not_null NOT NULL,
    authority_digest bytea CONSTRAINT logical_workflow_activation_renewal_r_authority_digest_not_null NOT NULL,
    predecessor_generation bigint CONSTRAINT logical_workflow_activation_ren_predecessor_generation_not_null NOT NULL,
    predecessor_claimed_at_ms bigint CONSTRAINT logical_workflow_activation__predecessor_claimed_at_ms_not_null NOT NULL,
    predecessor_expires_at_ms bigint CONSTRAINT logical_workflow_activation__predecessor_expires_at_ms_not_null NOT NULL,
    requested_duration_ms bigint CONSTRAINT logical_workflow_activation_rene_requested_duration_ms_not_null NOT NULL,
    successor_generation bigint CONSTRAINT logical_workflow_activation_renew_successor_generation_not_null NOT NULL,
    successor_claimed_at_ms bigint CONSTRAINT logical_workflow_activation_re_successor_claimed_at_ms_not_null NOT NULL,
    successor_expires_at_ms bigint CONSTRAINT logical_workflow_activation_re_successor_expires_at_ms_not_null NOT NULL,
    validated_at_ms bigint CONSTRAINT logical_workflow_activation_renewal_re_validated_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_activation_renewal_shape CHECK (((authority_kind = ANY (ARRAY['preparation'::text, 'activation'::text])) AND (selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32) AND (octet_length(authority_digest) = 32) AND (predecessor_generation > 0) AND (successor_generation = (predecessor_generation + 1)) AND (predecessor_claimed_at_ms >= 0) AND (predecessor_expires_at_ms > predecessor_claimed_at_ms) AND ((requested_duration_ms >= 2000) AND (requested_duration_ms <= 900000)) AND (successor_claimed_at_ms >= predecessor_claimed_at_ms) AND (successor_claimed_at_ms < predecessor_expires_at_ms) AND (successor_expires_at_ms = (successor_claimed_at_ms + requested_duration_ms)) AND (successor_expires_at_ms > predecessor_expires_at_ms) AND (validated_at_ms >= successor_claimed_at_ms) AND (validated_at_ms < successor_expires_at_ms)))
);

CREATE TABLE logical_workflow_activation_work_quarantines (
    logical_job_id uuid CONSTRAINT logical_workflow_activation_work_quaran_logical_job_id_not_null NOT NULL,
    tenant_id text NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_activation_work_quarant_invocation_id_not_null NOT NULL,
    selection_id uuid CONSTRAINT logical_workflow_activation_work_quaranti_selection_id_not_null NOT NULL,
    selection_owner_id uuid CONSTRAINT logical_workflow_activation_work_qu_selection_owner_id_not_null NOT NULL,
    selection_requested_at_ms bigint CONSTRAINT logical_workflow_activation__selection_requested_at_ms_not_null NOT NULL,
    selection_duration_ms bigint CONSTRAINT logical_workflow_activation_wor_selection_duration_ms_not_null1 NOT NULL,
    selection_generation bigint CONSTRAINT logical_workflow_activation_work__selection_generation_not_null NOT NULL,
    selection_claimed_at_ms bigint CONSTRAINT logical_workflow_activation_wo_selection_claimed_at_ms_not_null NOT NULL,
    selection_expires_at_ms bigint CONSTRAINT logical_workflow_activation_wo_selection_expires_at_ms_not_null NOT NULL,
    authority_kind text CONSTRAINT logical_workflow_activation_work_quaran_authority_kind_not_null NOT NULL,
    authority_digest bytea CONSTRAINT logical_workflow_activation_work_quar_authority_digest_not_null NOT NULL,
    authority_owner_id uuid CONSTRAINT logical_workflow_activation_work_qu_authority_owner_id_not_null NOT NULL,
    authority_generation bigint CONSTRAINT logical_workflow_activation_work__authority_generation_not_null NOT NULL,
    authority_claimed_at_ms bigint CONSTRAINT logical_workflow_activation_wo_authority_claimed_at_ms_not_null NOT NULL,
    authority_expires_at_ms bigint CONSTRAINT logical_workflow_activation_wo_authority_expires_at_ms_not_null NOT NULL,
    failure_kind text CONSTRAINT logical_workflow_activation_work_quaranti_failure_kind_not_null NOT NULL,
    quarantined_at_ms bigint CONSTRAINT logical_workflow_activation_work_qua_quarantined_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_activation_quarantine_shape CHECK (((selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (selection_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (authority_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (selection_generation > 0) AND (authority_generation >= selection_generation) AND (selection_requested_at_ms >= 0) AND ((selection_duration_ms >= 2000) AND (selection_duration_ms <= 300000)) AND (selection_claimed_at_ms >= 0) AND (selection_expires_at_ms = (selection_claimed_at_ms + selection_duration_ms)) AND (authority_kind = ANY (ARRAY['preparation'::text, 'activation'::text])) AND (octet_length(authority_digest) = 32) AND (authority_claimed_at_ms >= 0) AND (authority_expires_at_ms > authority_claimed_at_ms) AND (failure_kind = ANY (ARRAY['relational_evidence'::text, 'object_evidence'::text, 'payload_evidence'::text, 'generation_exhausted'::text])) AND (quarantined_at_ms >= 0)))
);

CREATE TABLE logical_workflow_activation_work_selections (
    selection_id uuid CONSTRAINT logical_workflow_activation_work_selectio_selection_id_not_null NOT NULL,
    owner_id uuid NOT NULL,
    requested_at_ms bigint CONSTRAINT logical_workflow_activation_work_selec_requested_at_ms_not_null NOT NULL,
    duration_ms bigint CONSTRAINT logical_workflow_activation_work_selection_duration_ms_not_null NOT NULL,
    claimed_at_ms bigint,
    expires_at_ms bigint,
    outcome text NOT NULL,
    tenant_id text,
    run_id uuid,
    invocation_id uuid,
    logical_job_id uuid,
    generation bigint,
    authority_kind text,
    authority_digest bytea,
    CONSTRAINT logical_workflow_activation_selection_identity CHECK (((selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (requested_at_ms >= 0) AND ((duration_ms >= 2000) AND (duration_ms <= 300000)))),
    CONSTRAINT logical_workflow_activation_selection_shape CHECK (((((outcome = 'selecting'::text) AND (claimed_at_ms IS NULL) AND (expires_at_ms IS NULL) AND (tenant_id IS NULL) AND (run_id IS NULL) AND (invocation_id IS NULL) AND (logical_job_id IS NULL) AND (generation IS NULL) AND (authority_kind IS NULL) AND (authority_digest IS NULL)) OR ((outcome = ANY (ARRAY['idle'::text, 'contended'::text, 'claimed'::text, 'quarantined'::text])) AND (claimed_at_ms >= 0) AND (expires_at_ms = (claimed_at_ms + duration_ms)) AND (((outcome = ANY (ARRAY['idle'::text, 'contended'::text])) AND (tenant_id IS NULL) AND (run_id IS NULL) AND (invocation_id IS NULL) AND (logical_job_id IS NULL) AND (generation IS NULL) AND (authority_kind IS NULL) AND (authority_digest IS NULL)) OR ((outcome = ANY (ARRAY['claimed'::text, 'quarantined'::text])) AND (tenant_id IS NOT NULL) AND (run_id IS NOT NULL) AND (invocation_id IS NOT NULL) AND (logical_job_id IS NOT NULL) AND (generation > 0) AND (authority_kind = ANY (ARRAY['preparation'::text, 'activation'::text])) AND (octet_length(authority_digest) = 32))))) IS TRUE))
);

CREATE TABLE logical_workflow_concrete_jobs (
    instance_id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    descriptor_digest bytea NOT NULL,
    job_id uuid NOT NULL,
    initial_attempt_id uuid NOT NULL,
    job_key text NOT NULL COLLATE pg_catalog."C",
    display_name text NOT NULL COLLATE pg_catalog."C",
    requirements jsonb NOT NULL,
    requirements_digest bytea NOT NULL,
    commit_digest bytea NOT NULL,
    event_digest bytea NOT NULL,
    event_object_key text NOT NULL COLLATE pg_catalog."C",
    event_size_bytes bigint NOT NULL,
    event_media_type text NOT NULL COLLATE pg_catalog."C",
    runtime_context_digest bytea NOT NULL,
    runtime_context_object_key text CONSTRAINT logical_workflow_concrete_j_runtime_context_object_key_not_null NOT NULL COLLATE pg_catalog."C",
    runtime_context_size_bytes bigint CONSTRAINT logical_workflow_concrete_j_runtime_context_size_bytes_not_null NOT NULL,
    runtime_context_media_type text CONSTRAINT logical_workflow_concrete_j_runtime_context_media_type_not_null NOT NULL COLLATE pg_catalog."C",
    runtime_context_schema smallint NOT NULL,
    claim_owner_id uuid NOT NULL,
    claim_generation bigint NOT NULL,
    claim_started_at_ms bigint NOT NULL,
    claim_expires_at_ms bigint NOT NULL,
    committed_at_ms bigint NOT NULL,
    authority_profile text NOT NULL COLLATE pg_catalog."C",
    runtime_policy_revision bigint NOT NULL,
    runtime_policy_digest bytea NOT NULL,
    CONSTRAINT logical_workflow_concrete_jobs_authority_profile CHECK ((authority_profile = ANY (ARRAY['standard'::text, 'credential_free'::text]))),
    CONSTRAINT logical_workflow_concrete_jobs_claim_shape CHECK (((claim_generation > 0) AND (claim_started_at_ms >= 0) AND (claim_expires_at_ms > claim_started_at_ms) AND ((claim_expires_at_ms - claim_started_at_ms) <= 900000) AND (committed_at_ms >= claim_started_at_ms) AND (committed_at_ms < claim_expires_at_ms))),
    CONSTRAINT logical_workflow_concrete_jobs_digests_sha256 CHECK (((octet_length(descriptor_digest) = 32) AND (octet_length(requirements_digest) = 32) AND (octet_length(commit_digest) = 32) AND (octet_length(event_digest) = 32) AND (octet_length(runtime_context_digest) = 32))),
    CONSTRAINT logical_workflow_concrete_jobs_display_name_shape CHECK ((((octet_length(display_name) >= 1) AND (octet_length(display_name) <= 1024)) AND (btrim(display_name) <> ''::text) AND (display_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT logical_workflow_concrete_jobs_event_key_shape CHECK ((((octet_length(event_object_key) >= 1) AND (octet_length(event_object_key) <= 1024)) AND (event_object_key !~ '[[:cntrl:]]'::text) AND ("left"(event_object_key, 1) <> '/'::text) AND (event_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT logical_workflow_concrete_jobs_event_media_shape CHECK ((((octet_length(event_media_type) >= 3) AND (octet_length(event_media_type) <= 128)) AND (event_media_type ~~ '%/%'::text) AND (event_media_type !~ '[[:space:][:cntrl:];]'::text))),
    CONSTRAINT logical_workflow_concrete_jobs_event_size CHECK (((event_size_bytes >= 1) AND (event_size_bytes <= 26214400))),
    CONSTRAINT logical_workflow_concrete_jobs_ids_non_nil CHECK (((instance_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (initial_attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_concrete_jobs_job_key_shape CHECK ((((octet_length(job_key) >= 1) AND (octet_length(job_key) <= 512)) AND (btrim(job_key) = job_key) AND (job_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT logical_workflow_concrete_jobs_requirements_current CHECK (((requirements @> '{"schema_version": 1}'::jsonb) AND (requirements ? 'resource_allocation'::text))),
    CONSTRAINT logical_workflow_concrete_jobs_runtime_exact CHECK (((runtime_context_media_type = 'application/vnd.automata.job-runtime-context.protobuf'::text) AND (runtime_context_schema = 1))),
    CONSTRAINT logical_workflow_concrete_jobs_runtime_key_shape CHECK ((((octet_length(runtime_context_object_key) >= 1) AND (octet_length(runtime_context_object_key) <= 1024)) AND (runtime_context_object_key !~ '[[:cntrl:]]'::text) AND ("left"(runtime_context_object_key, 1) <> '/'::text) AND (runtime_context_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT logical_workflow_concrete_jobs_runtime_policy CHECK (((runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32))),
    CONSTRAINT logical_workflow_concrete_jobs_runtime_size CHECK (((runtime_context_size_bytes >= 1) AND (runtime_context_size_bytes <= 16777216)))
);

CREATE TABLE logical_workflow_concurrency_cancellations (
    run_id uuid NOT NULL,
    root_invocation_id uuid CONSTRAINT logical_workflow_concurrency_cancel_root_invocation_id_not_null NOT NULL,
    preempting_run_id uuid CONSTRAINT logical_workflow_concurrency_cancell_preempting_run_id_not_null NOT NULL,
    prior_workflow_status text CONSTRAINT logical_workflow_concurrency_can_prior_workflow_status_not_null NOT NULL,
    prior_workflow_updated_at_ms bigint CONSTRAINT logical_workflow_concurrenc_prior_workflow_updated_at__not_null NOT NULL,
    prior_marker_state text CONSTRAINT logical_workflow_concurrency_cancel_prior_marker_state_not_null NOT NULL,
    prior_marker_revision bigint CONSTRAINT logical_workflow_concurrency_can_prior_marker_revision_not_null NOT NULL,
    prior_marker_updated_at_ms bigint CONSTRAINT logical_workflow_concurrenc_prior_marker_updated_at_ms_not_null NOT NULL,
    prior_invocation_state text CONSTRAINT logical_workflow_concurrency_ca_prior_invocation_state_not_null NOT NULL,
    prior_invocation_revision bigint CONSTRAINT logical_workflow_concurrency_prior_invocation_revision_not_null NOT NULL,
    prior_invocation_updated_at_ms bigint CONSTRAINT logical_workflow_concurrenc_prior_invocation_updated_a_not_null NOT NULL,
    cancelled_at_ms bigint CONSTRAINT logical_workflow_concurrency_cancellat_cancelled_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_concurrency_cancellations_identity CHECK (((run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (preempting_run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (preempting_run_id <> run_id))),
    CONSTRAINT logical_workflow_concurrency_cancellations_prior_state CHECK (((prior_workflow_status = ANY (ARRAY['queued'::text, 'in_progress'::text])) AND (prior_marker_state = ANY (ARRAY['pending'::text, 'active'::text])) AND (prior_invocation_state = ANY (ARRAY['pending'::text, 'active'::text])) AND (prior_marker_revision > 0) AND (prior_invocation_revision > 0))),
    CONSTRAINT logical_workflow_concurrency_cancellations_time CHECK (((prior_workflow_updated_at_ms >= 0) AND (prior_marker_updated_at_ms >= 0) AND (prior_invocation_updated_at_ms >= 0) AND (cancelled_at_ms >= GREATEST(prior_workflow_updated_at_ms, prior_marker_updated_at_ms, prior_invocation_updated_at_ms))))
);

CREATE TABLE logical_workflow_dependencies (
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    prerequisite_job_id uuid NOT NULL,
    CONSTRAINT logical_workflow_dependencies_no_self_edge CHECK ((logical_job_id <> prerequisite_job_id))
);

CREATE TABLE logical_workflow_job_result_claims (
    logical_job_id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    descriptor_digest bytea NOT NULL,
    state text NOT NULL,
    owner_id uuid NOT NULL,
    generation bigint NOT NULL,
    claimed_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_job_result_claims_digest_sha256 CHECK ((octet_length(descriptor_digest) = 32)),
    CONSTRAINT logical_workflow_job_result_claims_generation CHECK ((generation > 0)),
    CONSTRAINT logical_workflow_job_result_claims_ids_non_nil CHECK (((logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_job_result_claims_interval CHECK (((claimed_at_ms >= 0) AND (expires_at_ms > claimed_at_ms) AND ((expires_at_ms - claimed_at_ms) <= 900000) AND (created_at_ms <= claimed_at_ms) AND (updated_at_ms >= claimed_at_ms))),
    CONSTRAINT logical_workflow_job_result_claims_state CHECK ((state = ANY (ARRAY['aggregating'::text, 'finalized'::text])))
);

CREATE TABLE logical_workflow_job_result_outputs (
    logical_job_id uuid NOT NULL,
    output_name text NOT NULL COLLATE pg_catalog."C",
    sensitivity text NOT NULL,
    public_value text,
    CONSTRAINT logical_workflow_job_result_outputs_classification CHECK ((((sensitivity = 'public'::text) AND (public_value IS NOT NULL) AND (octet_length(public_value) <= 2097152)) OR ((sensitivity = 'secret_derived'::text) AND (public_value IS NULL)))),
    CONSTRAINT logical_workflow_job_result_outputs_name_shape CHECK ((((octet_length(output_name) >= 1) AND (octet_length(output_name) <= 256)) AND (btrim(output_name) = output_name) AND (output_name !~ '[[:cntrl:]]'::text)))
);

CREATE TABLE workflow_rerun_carried_job_outputs (
    logical_job_id uuid NOT NULL,
    output_name text NOT NULL COLLATE pg_catalog."C",
    sensitivity text NOT NULL,
    public_value text,
    CONSTRAINT workflow_rerun_carried_job_outputs_classification CHECK ((((sensitivity = 'public'::text) AND (public_value IS NOT NULL) AND (octet_length(public_value) <= 2097152)) OR ((sensitivity = 'secret_derived'::text) AND (public_value IS NULL)))),
    CONSTRAINT workflow_rerun_carried_job_outputs_name_shape CHECK ((((octet_length(output_name) >= 1) AND (octet_length(output_name) <= 256)) AND (btrim(output_name) = output_name) AND (output_name !~ '[[:cntrl:]]'::text)))
);

CREATE VIEW logical_workflow_effective_job_result_outputs AS
 SELECT output.logical_job_id,
    output.output_name,
    output.sensitivity,
    output.public_value
   FROM (logical_workflow_job_result_outputs output
     JOIN logical_workflow_job_result_claims claim ON (((claim.logical_job_id = output.logical_job_id) AND (claim.state = 'finalized'::text))))
UNION ALL
 SELECT output.logical_job_id,
    output.output_name,
    output.sensitivity,
    output.public_value
   FROM workflow_rerun_carried_job_outputs output;

CREATE TABLE logical_workflow_job_results (
    logical_job_id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    descriptor_digest bytea NOT NULL,
    logical_key text NOT NULL COLLATE pg_catalog."C",
    source_order integer NOT NULL,
    plan_digest bytea NOT NULL,
    plan_object_key text NOT NULL COLLATE pg_catalog."C",
    plan_size_bytes bigint NOT NULL,
    plan_media_type text NOT NULL COLLATE pg_catalog."C",
    plan_schema smallint NOT NULL,
    activation_output_digest bytea NOT NULL,
    condition_matched boolean NOT NULL,
    instance_count integer NOT NULL,
    instances_digest bytea NOT NULL,
    prerequisite_count integer NOT NULL,
    prerequisites_digest bytea NOT NULL,
    effective_conclusion text NOT NULL,
    closure_has_failure boolean NOT NULL,
    closure_has_cancelled boolean NOT NULL,
    closure_has_skipped boolean NOT NULL,
    output_count integer NOT NULL,
    outputs_digest bytea NOT NULL,
    commit_digest bytea NOT NULL,
    claim_owner_id uuid NOT NULL,
    claim_generation bigint NOT NULL,
    claim_started_at_ms bigint NOT NULL,
    claim_expires_at_ms bigint NOT NULL,
    finalized_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_job_results_claim_shape CHECK (((claim_generation > 0) AND (claim_started_at_ms >= 0) AND (claim_expires_at_ms > claim_started_at_ms) AND ((claim_expires_at_ms - claim_started_at_ms) <= 900000) AND (finalized_at_ms >= claim_started_at_ms) AND (finalized_at_ms < claim_expires_at_ms))),
    CONSTRAINT logical_workflow_job_results_conclusion CHECK ((effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text]))),
    CONSTRAINT logical_workflow_job_results_counts CHECK ((((instance_count >= 0) AND (instance_count <= 256)) AND ((prerequisite_count >= 0) AND (prerequisite_count <= 128)) AND ((output_count >= 0) AND (output_count <= 256)) AND (condition_matched OR (instance_count = 0)))),
    CONSTRAINT logical_workflow_job_results_digests_sha256 CHECK (((octet_length(descriptor_digest) = 32) AND (octet_length(plan_digest) = 32) AND (octet_length(activation_output_digest) = 32) AND (octet_length(instances_digest) = 32) AND (octet_length(prerequisites_digest) = 32) AND (octet_length(outputs_digest) = 32) AND (octet_length(commit_digest) = 32))),
    CONSTRAINT logical_workflow_job_results_ids_non_nil CHECK (((logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_job_results_key_shape CHECK ((((octet_length(logical_key) >= 1) AND (octet_length(logical_key) <= 256)) AND (btrim(logical_key) = logical_key) AND (logical_key !~ '[[:cntrl:]]'::text) AND ((source_order >= 0) AND (source_order <= 1023)))),
    CONSTRAINT logical_workflow_job_results_plan_current CHECK ((((plan_size_bytes >= 1) AND (plan_size_bytes <= 16777216)) AND (plan_media_type = 'application/vnd.automata.workflow-plan+json'::text) AND (plan_schema = 1))),
    CONSTRAINT logical_workflow_job_results_plan_key_shape CHECK ((((octet_length(plan_object_key) >= 1) AND (octet_length(plan_object_key) <= 1024)) AND (plan_object_key !~ '[[:cntrl:]]'::text) AND ("left"(plan_object_key, 1) <> '/'::text) AND (plan_object_key !~ '(^|/)\.\.(/|$)'::text)))
);

CREATE TABLE workflow_rerun_carried_job_results (
    logical_job_id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    source_run_id uuid NOT NULL,
    source_logical_job_id uuid CONSTRAINT workflow_rerun_carried_job_resul_source_logical_job_id_not_null NOT NULL,
    result_descriptor_digest bytea CONSTRAINT workflow_rerun_carried_job_re_result_descriptor_digest_not_null NOT NULL,
    logical_key text NOT NULL COLLATE pg_catalog."C",
    source_order integer NOT NULL,
    plan_digest bytea NOT NULL,
    plan_object_key text NOT NULL COLLATE pg_catalog."C",
    plan_size_bytes bigint NOT NULL,
    plan_media_type text NOT NULL COLLATE pg_catalog."C",
    plan_schema smallint NOT NULL,
    activation_output_digest bytea CONSTRAINT workflow_rerun_carried_job_re_activation_output_digest_not_null NOT NULL,
    condition_matched boolean NOT NULL,
    instance_count integer NOT NULL,
    instances_digest bytea NOT NULL,
    prerequisite_count integer NOT NULL,
    prerequisites_digest bytea CONSTRAINT workflow_rerun_carried_job_result_prerequisites_digest_not_null NOT NULL,
    effective_conclusion text CONSTRAINT workflow_rerun_carried_job_result_effective_conclusion_not_null NOT NULL,
    closure_has_failure boolean NOT NULL,
    closure_has_cancelled boolean CONSTRAINT workflow_rerun_carried_job_resul_closure_has_cancelled_not_null NOT NULL,
    closure_has_skipped boolean NOT NULL,
    output_count integer NOT NULL,
    outputs_digest bytea NOT NULL,
    commit_digest bytea NOT NULL,
    claim_owner_id uuid NOT NULL,
    claim_generation bigint NOT NULL,
    claim_started_at_ms bigint NOT NULL,
    claim_expires_at_ms bigint NOT NULL,
    finalized_at_ms bigint NOT NULL,
    CONSTRAINT workflow_rerun_carried_job_results_digest_shape CHECK (((octet_length(result_descriptor_digest) = 32) AND (octet_length(plan_digest) = 32) AND (octet_length(activation_output_digest) = 32) AND (octet_length(instances_digest) = 32) AND (octet_length(prerequisites_digest) = 32) AND (octet_length(outputs_digest) = 32) AND (octet_length(commit_digest) = 32))),
    CONSTRAINT workflow_rerun_carried_job_results_ids_non_nil CHECK (((invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (source_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT workflow_rerun_carried_job_results_plan_key_shape CHECK ((((octet_length(plan_object_key) >= 1) AND (octet_length(plan_object_key) <= 1024)) AND (plan_object_key !~ '[[:cntrl:]]'::text) AND ("left"(plan_object_key, 1) <> '/'::text) AND (plan_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT workflow_rerun_carried_job_results_shape CHECK ((((source_order >= 0) AND (source_order <= 1023)) AND ((plan_size_bytes >= 1) AND (plan_size_bytes <= 16777216)) AND (plan_media_type = 'application/vnd.automata.workflow-plan+json'::text) AND (plan_schema = 1) AND ((instance_count >= 0) AND (instance_count <= 256)) AND ((prerequisite_count >= 0) AND (prerequisite_count <= 128)) AND ((output_count >= 0) AND (output_count <= 256)) AND (effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text])) AND (claim_generation > 0) AND (claim_started_at_ms >= 0) AND (claim_expires_at_ms > claim_started_at_ms) AND ((claim_expires_at_ms - claim_started_at_ms) <= 900000) AND (finalized_at_ms >= claim_started_at_ms) AND (finalized_at_ms < claim_expires_at_ms) AND (finalized_at_ms >= 0)))
);

CREATE VIEW logical_workflow_effective_job_results AS
 SELECT result.logical_job_id,
    result.run_id,
    result.invocation_id,
    result.descriptor_digest,
    result.logical_key,
    result.source_order,
    result.plan_digest,
    result.plan_object_key,
    result.plan_size_bytes,
    result.plan_media_type,
    result.plan_schema,
    result.activation_output_digest,
    result.condition_matched,
    result.instance_count,
    result.instances_digest,
    result.prerequisite_count,
    result.prerequisites_digest,
    result.effective_conclusion,
    result.closure_has_failure,
    result.closure_has_cancelled,
    result.closure_has_skipped,
    result.output_count,
    result.outputs_digest,
    result.commit_digest,
    result.claim_owner_id,
    result.claim_generation,
    result.claim_started_at_ms,
    result.claim_expires_at_ms,
    result.finalized_at_ms,
    claim.state AS claim_state,
    false AS carried
   FROM (logical_workflow_job_results result
     JOIN logical_workflow_job_result_claims claim ON (((claim.logical_job_id = result.logical_job_id) AND (claim.state = 'finalized'::text))))
UNION ALL
 SELECT carried.logical_job_id,
    carried.run_id,
    carried.invocation_id,
    carried.result_descriptor_digest AS descriptor_digest,
    carried.logical_key,
    carried.source_order,
    carried.plan_digest,
    carried.plan_object_key,
    carried.plan_size_bytes,
    carried.plan_media_type,
    carried.plan_schema,
    carried.activation_output_digest,
    carried.condition_matched,
    carried.instance_count,
    carried.instances_digest,
    carried.prerequisite_count,
    carried.prerequisites_digest,
    carried.effective_conclusion,
    carried.closure_has_failure,
    carried.closure_has_cancelled,
    carried.closure_has_skipped,
    carried.output_count,
    carried.outputs_digest,
    carried.commit_digest,
    carried.claim_owner_id,
    carried.claim_generation,
    carried.claim_started_at_ms,
    carried.claim_expires_at_ms,
    carried.finalized_at_ms,
    'finalized'::text AS claim_state,
    true AS carried
   FROM workflow_rerun_carried_job_results carried;

CREATE TABLE logical_workflow_instance_result_claims (
    attempt_id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    job_id uuid NOT NULL,
    descriptor_digest bytea CONSTRAINT logical_workflow_instance_result_cla_descriptor_digest_not_null NOT NULL,
    state text NOT NULL,
    owner_id uuid NOT NULL,
    generation bigint NOT NULL,
    claimed_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_instance_result_claims_digest_sha256 CHECK ((octet_length(descriptor_digest) = 32)),
    CONSTRAINT logical_workflow_instance_result_claims_generation CHECK ((generation > 0)),
    CONSTRAINT logical_workflow_instance_result_claims_ids_non_nil CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (instance_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_instance_result_claims_interval CHECK (((claimed_at_ms >= 0) AND (expires_at_ms > claimed_at_ms) AND ((expires_at_ms - claimed_at_ms) <= 900000))),
    CONSTRAINT logical_workflow_instance_result_claims_state CHECK ((state = ANY (ARRAY['projecting'::text, 'finalized'::text]))),
    CONSTRAINT logical_workflow_instance_result_claims_time_monotonic CHECK (((created_at_ms >= 0) AND (claimed_at_ms >= created_at_ms) AND (updated_at_ms >= claimed_at_ms)))
);

CREATE TABLE logical_workflow_instance_result_due (
    attempt_id uuid NOT NULL,
    tenant_id text NOT NULL COLLATE pg_catalog."C",
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    source_order integer NOT NULL,
    ready_at_ms bigint NOT NULL,
    available_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_instance_result_due_shape CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 255)) AND (tenant_id !~ '[[:cntrl:]]'::text) AND ((source_order >= 0) AND (source_order <= 1023)) AND (ready_at_ms >= 0) AND (available_at_ms >= ready_at_ms)))
);

CREATE TABLE logical_workflow_instance_result_outputs (
    instance_id uuid NOT NULL,
    output_name text NOT NULL COLLATE pg_catalog."C",
    sensitivity text NOT NULL,
    public_value text,
    CONSTRAINT logical_workflow_instance_result_outputs_classification CHECK ((((sensitivity = 'public'::text) AND (public_value IS NOT NULL) AND (public_value <> ''::text) AND (octet_length(public_value) <= 2097152)) OR ((sensitivity = 'secret_derived'::text) AND (public_value IS NULL)))),
    CONSTRAINT logical_workflow_instance_result_outputs_name_shape CHECK ((((octet_length(output_name) >= 1) AND (octet_length(output_name) <= 256)) AND (btrim(output_name) = output_name) AND (output_name !~ '[[:cntrl:]]'::text)))
);

CREATE TABLE logical_workflow_instance_result_quarantines (
    attempt_id uuid CONSTRAINT logical_workflow_instance_result_quarantine_attempt_id_not_null NOT NULL,
    tenant_id text NOT NULL COLLATE pg_catalog."C",
    run_id uuid NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_instance_result_quarant_invocation_id_not_null NOT NULL,
    logical_job_id uuid CONSTRAINT logical_workflow_instance_result_quaran_logical_job_id_not_null NOT NULL,
    source_order integer CONSTRAINT logical_workflow_instance_result_quaranti_source_order_not_null NOT NULL,
    ready_at_ms bigint CONSTRAINT logical_workflow_instance_result_quarantin_ready_at_ms_not_null NOT NULL,
    available_at_ms bigint CONSTRAINT logical_workflow_instance_result_quara_available_at_ms_not_null NOT NULL,
    failure_kind text CONSTRAINT logical_workflow_instance_result_quaranti_failure_kind_not_null NOT NULL,
    quarantined_at_ms bigint CONSTRAINT logical_workflow_instance_result_qua_quarantined_at_ms_not_null NOT NULL,
    claim_owner_id uuid,
    claim_generation bigint,
    claim_claimed_at_ms bigint,
    claim_expires_at_ms bigint,
    claim_descriptor_digest bytea,
    CONSTRAINT logical_workflow_instance_result_quarantines_claim CHECK (((((claim_owner_id IS NULL) AND (claim_generation IS NULL) AND (claim_claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL) AND (claim_descriptor_digest IS NULL) AND (quarantined_at_ms >= available_at_ms)) OR ((claim_owner_id IS NOT NULL) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_generation > 0) AND (claim_claimed_at_ms >= 0) AND (quarantined_at_ms >= claim_claimed_at_ms) AND (claim_expires_at_ms > claim_claimed_at_ms) AND (quarantined_at_ms < claim_expires_at_ms) AND ((claim_expires_at_ms - claim_claimed_at_ms) <= 900000) AND (octet_length(claim_descriptor_digest) = 32))) IS TRUE)),
    CONSTRAINT logical_workflow_instance_result_quarantines_failure CHECK ((failure_kind = ANY (ARRAY['relational_evidence'::text, 'object_evidence'::text, 'payload_evidence'::text]))),
    CONSTRAINT logical_workflow_instance_result_quarantines_shape CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 255)) AND (tenant_id !~ '[[:cntrl:]]'::text) AND ((source_order >= 0) AND (source_order <= 1023)) AND (ready_at_ms >= 0) AND (available_at_ms >= ready_at_ms) AND (quarantined_at_ms >= ready_at_ms)))
);

CREATE TABLE logical_workflow_instance_result_selections (
    selection_id uuid CONSTRAINT logical_workflow_instance_result_selectio_selection_id_not_null NOT NULL,
    owner_id uuid NOT NULL,
    claimed_at_ms bigint CONSTRAINT logical_workflow_instance_result_selecti_claimed_at_ms_not_null NOT NULL,
    expires_at_ms bigint CONSTRAINT logical_workflow_instance_result_selecti_expires_at_ms_not_null NOT NULL,
    outcome text NOT NULL,
    tenant_id text COLLATE pg_catalog."C",
    attempt_id uuid,
    generation bigint,
    created_at_ms bigint CONSTRAINT logical_workflow_instance_result_selecti_created_at_ms_not_null NOT NULL,
    updated_at_ms bigint CONSTRAINT logical_workflow_instance_result_selecti_updated_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_instance_result_selections_ids_non_nil CHECK (((selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((attempt_id IS NULL) OR (attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT logical_workflow_instance_result_selections_interval CHECK (((claimed_at_ms >= 0) AND (expires_at_ms > claimed_at_ms) AND ((expires_at_ms - claimed_at_ms) <= 900000) AND (created_at_ms = claimed_at_ms) AND (updated_at_ms >= created_at_ms))),
    CONSTRAINT logical_workflow_instance_result_selections_outcome CHECK ((((outcome = ANY (ARRAY['selecting'::text, 'idle'::text])) AND (tenant_id IS NULL) AND (attempt_id IS NULL) AND (generation IS NULL)) OR ((outcome = 'claimed'::text) AND (tenant_id IS NOT NULL) AND (attempt_id IS NOT NULL) AND (generation > 0)) OR ((outcome = 'quarantined'::text) AND (tenant_id IS NOT NULL) AND (attempt_id IS NOT NULL) AND (generation IS NULL)))),
    CONSTRAINT logical_workflow_instance_result_selections_tenant CHECK (((tenant_id IS NULL) OR (((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 255)) AND (tenant_id !~ '[[:cntrl:]]'::text))))
);

CREATE TABLE logical_workflow_instance_results (
    instance_id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    descriptor_digest bytea NOT NULL,
    result_digest bytea,
    result_object_key text COLLATE pg_catalog."C",
    result_size_bytes bigint,
    result_media_type text COLLATE pg_catalog."C",
    result_schema smallint,
    job_ir_digest bytea NOT NULL,
    job_ir_object_key text NOT NULL COLLATE pg_catalog."C",
    job_ir_size_bytes bigint NOT NULL,
    job_ir_media_type text NOT NULL COLLATE pg_catalog."C",
    job_ir_schema smallint NOT NULL,
    raw_conclusion text NOT NULL,
    effective_conclusion text NOT NULL,
    continue_on_error boolean NOT NULL,
    secret_exposure_class text CONSTRAINT logical_workflow_instance_result_secret_exposure_class_not_null NOT NULL,
    result_completed_at_ms bigint CONSTRAINT logical_workflow_instance_resul_result_completed_at_ms_not_null NOT NULL,
    result_committed_at_ms bigint CONSTRAINT logical_workflow_instance_resul_result_committed_at_ms_not_null NOT NULL,
    output_count integer NOT NULL,
    outputs_digest bytea NOT NULL,
    commit_digest bytea NOT NULL,
    claim_owner_id uuid NOT NULL,
    claim_generation bigint NOT NULL,
    claim_started_at_ms bigint NOT NULL,
    claim_expires_at_ms bigint NOT NULL,
    finalized_at_ms bigint NOT NULL,
    terminal_ordinal bigint NOT NULL,
    terminal_authority text NOT NULL,
    server_cancellation_operation_id uuid,
    server_cancellation_digest bytea,
    CONSTRAINT logical_workflow_instance_results_claim_shape CHECK (((claim_generation > 0) AND (claim_started_at_ms >= result_committed_at_ms) AND (claim_expires_at_ms > claim_started_at_ms) AND ((claim_expires_at_ms - claim_started_at_ms) <= 900000) AND (finalized_at_ms >= claim_started_at_ms) AND (finalized_at_ms < claim_expires_at_ms))),
    CONSTRAINT logical_workflow_instance_results_coe_mapping CHECK (((continue_on_error AND (raw_conclusion = 'failure'::text) AND (effective_conclusion = 'success'::text)) OR ((NOT (continue_on_error AND (raw_conclusion = 'failure'::text))) AND (effective_conclusion = raw_conclusion)))),
    CONSTRAINT logical_workflow_instance_results_common_digests_sha256 CHECK (((octet_length(descriptor_digest) = 32) AND (octet_length(job_ir_digest) = 32) AND (octet_length(outputs_digest) = 32) AND (octet_length(commit_digest) = 32))),
    CONSTRAINT logical_workflow_instance_results_conclusions CHECK (((raw_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text])) AND (effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text])))),
    CONSTRAINT logical_workflow_instance_results_ids_non_nil CHECK (((instance_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_instance_results_job_ir_current CHECK ((((job_ir_size_bytes >= 1) AND (job_ir_size_bytes <= 16777216)) AND (job_ir_media_type = 'application/vnd.automata.job-ir.protobuf'::text) AND (job_ir_schema = 1))),
    CONSTRAINT logical_workflow_instance_results_job_ir_key_shape CHECK ((((octet_length(job_ir_object_key) >= 1) AND (octet_length(job_ir_object_key) <= 1024)) AND (job_ir_object_key !~ '[[:cntrl:]]'::text) AND ("left"(job_ir_object_key, 1) <> '/'::text) AND (job_ir_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT logical_workflow_instance_results_output_count CHECK (((output_count >= 0) AND (output_count <= 1024))),
    CONSTRAINT logical_workflow_instance_results_result_time CHECK (((result_completed_at_ms >= 0) AND (result_committed_at_ms >= result_completed_at_ms))),
    CONSTRAINT logical_workflow_instance_results_secret_exposure CHECK ((secret_exposure_class = ANY (ARRAY['secretless'::text, 'capability_only'::text, 'readable_secret'::text]))),
    CONSTRAINT logical_workflow_instance_results_server_digest_sha256 CHECK (((server_cancellation_digest IS NULL) OR (octet_length(server_cancellation_digest) = 32))),
    CONSTRAINT logical_workflow_instance_results_terminal_authority_shape CHECK (((((terminal_authority = 'runner'::text) AND (octet_length(result_digest) = 32) AND ((octet_length(result_object_key) >= 1) AND (octet_length(result_object_key) <= 1024)) AND (result_object_key !~ '[[:cntrl:]]'::text) AND ("left"(result_object_key, 1) <> '/'::text) AND (result_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((result_size_bytes >= 1) AND (result_size_bytes <= 16777216)) AND (result_media_type = 'application/vnd.automata.job-result+json'::text) AND (result_schema = 1) AND (server_cancellation_operation_id IS NULL) AND (server_cancellation_digest IS NULL)) OR ((terminal_authority = 'server_cancellation'::text) AND (result_digest IS NULL) AND (result_object_key IS NULL) AND (result_size_bytes IS NULL) AND (result_media_type IS NULL) AND (result_schema IS NULL) AND (server_cancellation_operation_id IS NOT NULL) AND (server_cancellation_digest IS NOT NULL) AND (raw_conclusion = 'cancelled'::text) AND (effective_conclusion = 'cancelled'::text) AND (secret_exposure_class = 'secretless'::text) AND (output_count = 0))) IS TRUE)),
    CONSTRAINT logical_workflow_instance_results_terminal_ordinal_positive CHECK ((terminal_ordinal > 0))
);

CREATE TABLE logical_workflow_instances (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    matrix_index integer NOT NULL,
    matrix_total integer NOT NULL,
    matrix_digest bytea NOT NULL,
    workspace text NOT NULL COLLATE pg_catalog."C",
    job_ir_digest bytea NOT NULL,
    job_ir_object_key text NOT NULL COLLATE pg_catalog."C",
    job_ir_size_bytes bigint NOT NULL,
    job_ir_media_type text NOT NULL COLLATE pg_catalog."C",
    job_ir_version smallint NOT NULL,
    runtime_context_digest bytea NOT NULL,
    runtime_context_object_key text NOT NULL COLLATE pg_catalog."C",
    runtime_context_size_bytes bigint NOT NULL,
    runtime_context_media_type text NOT NULL COLLATE pg_catalog."C",
    runtime_context_schema smallint NOT NULL,
    created_at_ms bigint NOT NULL,
    runtime_policy_revision bigint NOT NULL,
    runtime_policy_digest bytea NOT NULL,
    CONSTRAINT logical_workflow_instances_context_key_shape CHECK ((((octet_length(runtime_context_object_key) >= 1) AND (octet_length(runtime_context_object_key) <= 1024)) AND (runtime_context_object_key !~ '[[:cntrl:]]'::text) AND ("left"(runtime_context_object_key, 1) <> '/'::text) AND (runtime_context_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT logical_workflow_instances_context_media_exact CHECK (((runtime_context_media_type = 'application/vnd.automata.job-runtime-context.protobuf'::text) AND (runtime_context_schema = 1))),
    CONSTRAINT logical_workflow_instances_context_sha256 CHECK ((octet_length(runtime_context_digest) = 32)),
    CONSTRAINT logical_workflow_instances_context_size CHECK (((runtime_context_size_bytes >= 1) AND (runtime_context_size_bytes <= 16777216))),
    CONSTRAINT logical_workflow_instances_id_non_nil CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_instances_job_ir_key_shape CHECK ((((octet_length(job_ir_object_key) >= 1) AND (octet_length(job_ir_object_key) <= 1024)) AND (job_ir_object_key !~ '[[:cntrl:]]'::text) AND ("left"(job_ir_object_key, 1) <> '/'::text) AND (job_ir_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT logical_workflow_instances_job_ir_media_exact CHECK (((job_ir_media_type = 'application/vnd.automata.job-ir.protobuf'::text) AND (job_ir_version = 1))),
    CONSTRAINT logical_workflow_instances_job_ir_sha256 CHECK ((octet_length(job_ir_digest) = 32)),
    CONSTRAINT logical_workflow_instances_job_ir_size CHECK (((job_ir_size_bytes >= 1) AND (job_ir_size_bytes <= 16777216))),
    CONSTRAINT logical_workflow_instances_matrix_shape CHECK ((((matrix_index >= 0) AND (matrix_index <= 255)) AND ((matrix_total >= 1) AND (matrix_total <= 256)) AND (matrix_index < matrix_total) AND (octet_length(matrix_digest) = 32))),
    CONSTRAINT logical_workflow_instances_runtime_policy CHECK (((runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32))),
    CONSTRAINT logical_workflow_instances_time_nonnegative CHECK ((created_at_ms >= 0)),
    CONSTRAINT logical_workflow_instances_workspace_shape CHECK ((((octet_length(workspace) >= 2) AND (octet_length(workspace) <= 1024)) AND (workspace !~ '[[:cntrl:]]'::text) AND (("left"(workspace, 1) = '/'::text) OR (workspace ~ '^[A-Za-z]:\\'::text))))
);

CREATE TABLE logical_workflow_invocations (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    plan_digest bytea NOT NULL,
    plan_object_key text NOT NULL COLLATE pg_catalog."C",
    plan_size_bytes bigint NOT NULL,
    plan_media_type text NOT NULL COLLATE pg_catalog."C",
    plan_schema smallint NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    invocation_kind text DEFAULT 'root'::text NOT NULL,
    CONSTRAINT logical_workflow_invocations_id_non_nil CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_invocations_kind CHECK ((invocation_kind = ANY (ARRAY['root'::text, 'reusable'::text]))),
    CONSTRAINT logical_workflow_invocations_media_type_shape CHECK ((((octet_length(plan_media_type) >= 3) AND (octet_length(plan_media_type) <= 128)) AND (plan_media_type ~~ '%/%'::text) AND (plan_media_type !~ '[[:space:][:cntrl:];]'::text))),
    CONSTRAINT logical_workflow_invocations_object_key_shape CHECK ((((octet_length(plan_object_key) >= 1) AND (octet_length(plan_object_key) <= 1024)) AND (plan_object_key !~ '[[:cntrl:]]'::text) AND ("left"(plan_object_key, 1) <> '/'::text) AND (plan_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT logical_workflow_invocations_plan_sha256 CHECK ((octet_length(plan_digest) = 32)),
    CONSTRAINT logical_workflow_invocations_plan_size CHECK (((plan_size_bytes >= 1) AND (plan_size_bytes <= 16777216))),
    CONSTRAINT logical_workflow_invocations_revision_positive CHECK ((revision > 0)),
    CONSTRAINT logical_workflow_invocations_schema_exact CHECK ((plan_schema = 1)),
    CONSTRAINT logical_workflow_invocations_state CHECK ((state = ANY (ARRAY['pending'::text, 'active'::text, 'completed'::text, 'cancelled'::text, 'failed'::text]))),
    CONSTRAINT logical_workflow_invocations_time_monotonic CHECK (((created_at_ms >= 0) AND (updated_at_ms >= created_at_ms)))
);

CREATE TABLE logical_workflow_job_environment_evidence (
    instance_id uuid NOT NULL,
    environment_normalized_name text COLLATE pg_catalog."C",
    event_trust text NOT NULL,
    source_kind text NOT NULL,
    reusable_secret_permission text CONSTRAINT logical_workflow_job_enviro_reusable_secret_permission_not_null NOT NULL,
    created_at_ms bigint CONSTRAINT logical_workflow_job_environment_evidenc_created_at_ms_not_null NOT NULL,
    CONSTRAINT job_environment_evidence_created_at CHECK ((created_at_ms >= 0)),
    CONSTRAINT job_environment_evidence_environment CHECK (((environment_normalized_name IS NULL) OR (((octet_length(environment_normalized_name) >= 1) AND (octet_length(environment_normalized_name) <= 255)) AND (environment_normalized_name = lower(environment_normalized_name)) AND (environment_normalized_name !~ '[[:cntrl:]]'::text) AND (btrim(environment_normalized_name) = environment_normalized_name)))),
    CONSTRAINT job_environment_evidence_event_trust CHECK ((event_trust = ANY (ARRAY['trusted'::text, 'untrusted'::text]))),
    CONSTRAINT job_environment_evidence_reusable_permission CHECK ((reusable_secret_permission = ANY (ARRAY['none'::text, 'explicit'::text]))),
    CONSTRAINT job_environment_evidence_source_kind CHECK ((source_kind = ANY (ARRAY['same_repository'::text, 'fork'::text, 'dependabot'::text]))),
    CONSTRAINT job_environment_evidence_source_trust CHECK (((source_kind = 'same_repository'::text) OR (event_trust = 'untrusted'::text)))
);

CREATE TABLE logical_workflow_job_result_due (
    logical_job_id uuid NOT NULL,
    tenant_id text NOT NULL COLLATE pg_catalog."C",
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    source_order integer NOT NULL,
    ready_at_ms bigint NOT NULL,
    available_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_job_result_due_shape CHECK (((logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 255)) AND (tenant_id !~ '[[:cntrl:]]'::text) AND ((source_order >= 0) AND (source_order <= 1023)) AND (ready_at_ms >= 0) AND (available_at_ms >= ready_at_ms)))
);

CREATE TABLE logical_workflow_job_result_instances (
    logical_job_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    matrix_index integer NOT NULL,
    terminal_ordinal bigint NOT NULL,
    instance_descriptor_digest bytea CONSTRAINT logical_workflow_job_result_instance_descriptor_digest_not_null NOT NULL,
    instance_outputs_digest bytea CONSTRAINT logical_workflow_job_result_in_instance_outputs_digest_not_null NOT NULL,
    instance_commit_digest bytea CONSTRAINT logical_workflow_job_result_ins_instance_commit_digest_not_null NOT NULL,
    raw_conclusion text NOT NULL,
    effective_conclusion text CONSTRAINT logical_workflow_job_result_insta_effective_conclusion_not_null NOT NULL,
    CONSTRAINT logical_workflow_job_result_instances_shape CHECK (((instance_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((matrix_index >= 0) AND (matrix_index <= 255)) AND (terminal_ordinal > 0) AND (octet_length(instance_descriptor_digest) = 32) AND (octet_length(instance_outputs_digest) = 32) AND (octet_length(instance_commit_digest) = 32) AND (raw_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text])) AND (effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text]))))
);

CREATE TABLE logical_workflow_job_result_prerequisites (
    logical_job_id uuid CONSTRAINT logical_workflow_job_result_prerequisit_logical_job_id_not_null NOT NULL,
    prerequisite_job_id uuid CONSTRAINT logical_workflow_job_result_prereq_prerequisite_job_id_not_null NOT NULL,
    prerequisite_source_order integer CONSTRAINT logical_workflow_job_result__prerequisite_source_order_not_null NOT NULL,
    prerequisite_commit_digest bytea CONSTRAINT logical_workflow_job_result_prerequisite_commit_digest_not_null NOT NULL,
    prerequisite_outputs_digest bytea CONSTRAINT logical_workflow_job_result_prerequisite_outputs_diges_not_null NOT NULL,
    effective_conclusion text CONSTRAINT logical_workflow_job_result_prere_effective_conclusion_not_null NOT NULL,
    closure_has_failure boolean CONSTRAINT logical_workflow_job_result_prereq_closure_has_failure_not_null NOT NULL,
    closure_has_cancelled boolean CONSTRAINT logical_workflow_job_result_prer_closure_has_cancelled_not_null NOT NULL,
    closure_has_skipped boolean CONSTRAINT logical_workflow_job_result_prereq_closure_has_skipped_not_null NOT NULL,
    CONSTRAINT logical_workflow_job_result_prerequisites_shape CHECK (((prerequisite_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((prerequisite_source_order >= 0) AND (prerequisite_source_order <= 1023)) AND (octet_length(prerequisite_commit_digest) = 32) AND (octet_length(prerequisite_outputs_digest) = 32) AND (effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text]))))
);

CREATE TABLE logical_workflow_job_result_quarantines (
    logical_job_id uuid NOT NULL,
    tenant_id text NOT NULL COLLATE pg_catalog."C",
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    source_order integer NOT NULL,
    ready_at_ms bigint NOT NULL,
    available_at_ms bigint CONSTRAINT logical_workflow_job_result_quarantine_available_at_ms_not_null NOT NULL,
    failure_kind text NOT NULL,
    quarantined_at_ms bigint CONSTRAINT logical_workflow_job_result_quaranti_quarantined_at_ms_not_null NOT NULL,
    claim_owner_id uuid,
    claim_generation bigint,
    claim_claimed_at_ms bigint,
    claim_expires_at_ms bigint,
    claim_descriptor_digest bytea,
    CONSTRAINT logical_workflow_job_result_quarantines_claim CHECK (((((claim_owner_id IS NULL) AND (claim_generation IS NULL) AND (claim_claimed_at_ms IS NULL) AND (claim_expires_at_ms IS NULL) AND (claim_descriptor_digest IS NULL) AND (quarantined_at_ms >= available_at_ms)) OR ((claim_owner_id IS NOT NULL) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_generation > 0) AND (claim_claimed_at_ms >= 0) AND (quarantined_at_ms >= claim_claimed_at_ms) AND (claim_expires_at_ms > claim_claimed_at_ms) AND (quarantined_at_ms < claim_expires_at_ms) AND ((claim_expires_at_ms - claim_claimed_at_ms) <= 900000) AND (octet_length(claim_descriptor_digest) = 32))) IS TRUE)),
    CONSTRAINT logical_workflow_job_result_quarantines_failure CHECK ((failure_kind = ANY (ARRAY['relational_evidence'::text, 'object_evidence'::text, 'payload_evidence'::text]))),
    CONSTRAINT logical_workflow_job_result_quarantines_shape CHECK (((logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 255)) AND (tenant_id !~ '[[:cntrl:]]'::text) AND ((source_order >= 0) AND (source_order <= 1023)) AND (ready_at_ms >= 0) AND (available_at_ms >= ready_at_ms) AND (quarantined_at_ms >= ready_at_ms)))
);

CREATE TABLE logical_workflow_job_result_selections (
    selection_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    claimed_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    outcome text NOT NULL,
    tenant_id text COLLATE pg_catalog."C",
    run_id uuid,
    invocation_id uuid,
    logical_job_id uuid,
    generation bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_job_result_selections_ids_non_nil CHECK (((selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((run_id IS NULL) OR (run_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((invocation_id IS NULL) OR (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid)) AND ((logical_job_id IS NULL) OR (logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid)))),
    CONSTRAINT logical_workflow_job_result_selections_interval CHECK (((claimed_at_ms >= 0) AND (expires_at_ms > claimed_at_ms) AND ((expires_at_ms - claimed_at_ms) <= 900000) AND (created_at_ms = claimed_at_ms) AND (updated_at_ms >= created_at_ms))),
    CONSTRAINT logical_workflow_job_result_selections_outcome CHECK ((((outcome = ANY (ARRAY['selecting'::text, 'idle'::text])) AND (tenant_id IS NULL) AND (run_id IS NULL) AND (invocation_id IS NULL) AND (logical_job_id IS NULL) AND (generation IS NULL)) OR ((outcome = 'claimed'::text) AND (tenant_id IS NOT NULL) AND (run_id IS NOT NULL) AND (invocation_id IS NOT NULL) AND (logical_job_id IS NOT NULL) AND (generation > 0)) OR ((outcome = 'quarantined'::text) AND (tenant_id IS NOT NULL) AND (run_id IS NOT NULL) AND (invocation_id IS NOT NULL) AND (logical_job_id IS NOT NULL) AND (generation IS NULL)))),
    CONSTRAINT logical_workflow_job_result_selections_tenant CHECK (((tenant_id IS NULL) OR (((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 255)) AND (tenant_id !~ '[[:cntrl:]]'::text))))
);

CREATE TABLE logical_workflow_job_terminal_counters (
    logical_job_id uuid NOT NULL,
    last_ordinal bigint NOT NULL,
    CONSTRAINT logical_workflow_job_terminal_counters_positive CHECK ((last_ordinal > 0))
);

CREATE TABLE logical_workflow_jobs (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_key text NOT NULL COLLATE pg_catalog."C",
    source_order integer NOT NULL,
    execution_kind text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    activation_fence bigint DEFAULT 0 NOT NULL,
    activation_owner_id uuid,
    activation_claimed_at_ms bigint,
    activation_expires_at_ms bigint,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    activation_input_digest bytea,
    authority_profile text COLLATE pg_catalog."C",
    runtime_policy_revision bigint NOT NULL,
    runtime_policy_digest bytea NOT NULL,
    activation_origin_selection_id uuid,
    environment_requirement_kind text DEFAULT 'unclassified'::text NOT NULL,
    environment_template_digest bytea,
    secret_reference_names text[] DEFAULT '{}'::text[] NOT NULL,
    variable_reference_names text[] DEFAULT '{}'::text[] NOT NULL,
    credential_requirements_schema smallint DEFAULT 1 NOT NULL,
    rerun_carried boolean DEFAULT false NOT NULL,
    CONSTRAINT logical_workflow_jobs_activation_input_digest CHECK (((activation_input_digest IS NULL) OR (octet_length(activation_input_digest) = 32))),
    CONSTRAINT logical_workflow_jobs_activation_origin_shape CHECK (((activation_origin_selection_id IS NULL) OR (activation_origin_selection_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_jobs_authority_profile CHECK (((authority_profile IS NULL) OR (authority_profile = ANY (ARRAY['standard'::text, 'credential_free'::text])))),
    CONSTRAINT logical_workflow_jobs_claim_shape CHECK (((((activation_owner_id IS NULL) AND (activation_claimed_at_ms IS NULL) AND (activation_expires_at_ms IS NULL) AND (state <> 'activating'::text) AND ((activation_fence > 0) OR (state = ANY (ARRAY['pending'::text, 'cancelled'::text])))) OR ((activation_owner_id IS NOT NULL) AND (activation_fence > 0) AND (state = 'activating'::text) AND (activation_claimed_at_ms >= created_at_ms) AND (activation_expires_at_ms > activation_claimed_at_ms) AND ((activation_expires_at_ms - activation_claimed_at_ms) <= 900000) AND (updated_at_ms = activation_claimed_at_ms))) IS TRUE)),
    CONSTRAINT logical_workflow_jobs_credential_schema CHECK ((credential_requirements_schema = 1)),
    CONSTRAINT logical_workflow_jobs_environment_requirement CHECK ((environment_requirement_kind = ANY (ARRAY['unclassified'::text, 'none'::text, 'environment'::text]))),
    CONSTRAINT logical_workflow_jobs_environment_requirement_shape CHECK (((((environment_requirement_kind = 'environment'::text) AND (octet_length(environment_template_digest) = 32)) OR ((environment_requirement_kind = ANY (ARRAY['unclassified'::text, 'none'::text])) AND (environment_template_digest IS NULL))) IS TRUE)),
    CONSTRAINT logical_workflow_jobs_execution_kind CHECK ((execution_kind = ANY (ARRAY['steps'::text, 'reusable_workflow'::text]))),
    CONSTRAINT logical_workflow_jobs_fence_nonnegative CHECK ((activation_fence >= 0)),
    CONSTRAINT logical_workflow_jobs_id_non_nil CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_jobs_key_shape CHECK ((((octet_length(logical_key) >= 1) AND (octet_length(logical_key) <= 256)) AND (btrim(logical_key) = logical_key) AND (logical_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT logical_workflow_jobs_owner_non_nil CHECK (((activation_owner_id IS NULL) OR (activation_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_jobs_reference_limits CHECK (((cardinality(secret_reference_names) <= 256) AND (cardinality(variable_reference_names) <= 256))),
    CONSTRAINT logical_workflow_jobs_runtime_policy CHECK (((runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32))),
    CONSTRAINT logical_workflow_jobs_source_order_bound CHECK (((source_order >= 0) AND (source_order <= 1023))),
    CONSTRAINT logical_workflow_jobs_state CHECK ((state = ANY (ARRAY['pending'::text, 'activating'::text, 'activated'::text, 'completed'::text, 'skipped'::text, 'cancelled'::text, 'failed'::text]))),
    CONSTRAINT logical_workflow_jobs_time_monotonic CHECK (((created_at_ms >= 0) AND (updated_at_ms >= created_at_ms)))
);

CREATE TABLE logical_workflow_materialization_claims (
    instance_id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    descriptor_digest bytea CONSTRAINT logical_workflow_materialization_cla_descriptor_digest_not_null NOT NULL,
    expected_job_id uuid CONSTRAINT logical_workflow_materialization_claim_expected_job_id_not_null NOT NULL,
    expected_attempt_id uuid CONSTRAINT logical_workflow_materialization_c_expected_attempt_id_not_null NOT NULL,
    state text NOT NULL,
    owner_id uuid NOT NULL,
    generation bigint NOT NULL,
    claimed_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    authority_profile text CONSTRAINT logical_workflow_materialization_cla_authority_profile_not_null NOT NULL COLLATE pg_catalog."C",
    runtime_policy_revision bigint CONSTRAINT logical_workflow_materializati_runtime_policy_revision_not_null NOT NULL,
    runtime_policy_digest bytea CONSTRAINT logical_workflow_materialization_runtime_policy_digest_not_null NOT NULL,
    origin_selection_id uuid,
    CONSTRAINT logical_workflow_materialization_claims_authority_profile CHECK ((authority_profile = ANY (ARRAY['standard'::text, 'credential_free'::text]))),
    CONSTRAINT logical_workflow_materialization_claims_descriptor_sha256 CHECK ((octet_length(descriptor_digest) = 32)),
    CONSTRAINT logical_workflow_materialization_claims_generation_positive CHECK ((generation > 0)),
    CONSTRAINT logical_workflow_materialization_claims_ids_non_nil CHECK (((instance_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (expected_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (expected_attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_materialization_claims_interval CHECK (((claimed_at_ms >= 0) AND (expires_at_ms > claimed_at_ms) AND ((expires_at_ms - claimed_at_ms) <= 900000))),
    CONSTRAINT logical_workflow_materialization_claims_runtime_policy CHECK (((runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32))),
    CONSTRAINT logical_workflow_materialization_claims_state CHECK ((state = ANY (ARRAY['materializing'::text, 'materialized'::text]))),
    CONSTRAINT logical_workflow_materialization_claims_time_monotonic CHECK (((created_at_ms >= 0) AND (claimed_at_ms >= created_at_ms) AND (updated_at_ms >= claimed_at_ms))),
    CONSTRAINT logical_workflow_materialization_origin_shape CHECK (((origin_selection_id IS NULL) OR (origin_selection_id <> '00000000-0000-0000-0000-000000000000'::uuid)))
);

CREATE TABLE logical_workflow_materialization_renewal_receipts (
    instance_id uuid CONSTRAINT logical_workflow_materialization_renewal_r_instance_id_not_null NOT NULL,
    selection_id uuid CONSTRAINT logical_workflow_materialization_renewal__selection_id_not_null NOT NULL,
    tenant_id text CONSTRAINT logical_workflow_materialization_renewal_rec_tenant_id_not_null NOT NULL,
    run_id uuid CONSTRAINT logical_workflow_materialization_renewal_receip_run_id_not_null NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_materialization_renewal_invocation_id_not_null NOT NULL,
    logical_job_id uuid CONSTRAINT logical_workflow_materialization_renewa_logical_job_id_not_null NOT NULL,
    owner_id uuid CONSTRAINT logical_workflow_materialization_renewal_rece_owner_id_not_null NOT NULL,
    runtime_policy_revision bigint CONSTRAINT logical_workflow_materializat_runtime_policy_revision_not_null1 NOT NULL,
    runtime_policy_digest bytea CONSTRAINT logical_workflow_materializatio_runtime_policy_digest_not_null1 NOT NULL,
    authority_digest bytea CONSTRAINT logical_workflow_materialization_rene_authority_digest_not_null NOT NULL,
    expected_job_id uuid CONSTRAINT logical_workflow_materialization_renew_expected_job_id_not_null NOT NULL,
    expected_attempt_id uuid CONSTRAINT logical_workflow_materialization_r_expected_attempt_id_not_null NOT NULL,
    predecessor_generation bigint CONSTRAINT logical_workflow_materializatio_predecessor_generation_not_null NOT NULL,
    predecessor_claimed_at_ms bigint CONSTRAINT logical_workflow_materializa_predecessor_claimed_at_ms_not_null NOT NULL,
    predecessor_expires_at_ms bigint CONSTRAINT logical_workflow_materializa_predecessor_expires_at_ms_not_null NOT NULL,
    requested_duration_ms bigint CONSTRAINT logical_workflow_materialization_requested_duration_ms_not_null NOT NULL,
    successor_generation bigint CONSTRAINT logical_workflow_materialization__successor_generation_not_null NOT NULL,
    successor_claimed_at_ms bigint CONSTRAINT logical_workflow_materializati_successor_claimed_at_ms_not_null NOT NULL,
    successor_expires_at_ms bigint CONSTRAINT logical_workflow_materializati_successor_expires_at_ms_not_null NOT NULL,
    validated_at_ms bigint CONSTRAINT logical_workflow_materialization_renew_validated_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_materialization_renewal_shape CHECK (((selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (expected_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (expected_attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (runtime_policy_revision > 0) AND (octet_length(runtime_policy_digest) = 32) AND (octet_length(authority_digest) = 32) AND (predecessor_generation > 0) AND (successor_generation = (predecessor_generation + 1)) AND (predecessor_claimed_at_ms >= 0) AND (predecessor_expires_at_ms > predecessor_claimed_at_ms) AND ((requested_duration_ms >= 2000) AND (requested_duration_ms <= 900000)) AND (successor_claimed_at_ms >= predecessor_claimed_at_ms) AND (successor_claimed_at_ms < predecessor_expires_at_ms) AND (successor_expires_at_ms = (successor_claimed_at_ms + requested_duration_ms)) AND (successor_expires_at_ms > predecessor_expires_at_ms) AND (validated_at_ms >= successor_claimed_at_ms) AND (validated_at_ms < successor_expires_at_ms)))
);

CREATE TABLE logical_workflow_materialization_work_quarantines (
    instance_id uuid CONSTRAINT logical_workflow_materialization_work_quar_instance_id_not_null NOT NULL,
    tenant_id text CONSTRAINT logical_workflow_materialization_work_quaran_tenant_id_not_null NOT NULL,
    run_id uuid CONSTRAINT logical_workflow_materialization_work_quarantin_run_id_not_null NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_materialization_work_qu_invocation_id_not_null NOT NULL,
    logical_job_id uuid CONSTRAINT logical_workflow_materialization_work_q_logical_job_id_not_null NOT NULL,
    selection_id uuid CONSTRAINT logical_workflow_materialization_work_qua_selection_id_not_null NOT NULL,
    selection_owner_id uuid CONSTRAINT logical_workflow_materialization_wo_selection_owner_id_not_null NOT NULL,
    selection_requested_at_ms bigint CONSTRAINT logical_workflow_materializa_selection_requested_at_ms_not_null NOT NULL,
    selection_duration_ms bigint CONSTRAINT logical_workflow_materialization_selection_duration_ms_not_null NOT NULL,
    selection_generation bigint CONSTRAINT logical_workflow_materialization__selection_generation_not_null NOT NULL,
    selection_claimed_at_ms bigint CONSTRAINT logical_workflow_materializati_selection_claimed_at_ms_not_null NOT NULL,
    selection_expires_at_ms bigint CONSTRAINT logical_workflow_materializati_selection_expires_at_ms_not_null NOT NULL,
    authority_digest bytea CONSTRAINT logical_workflow_materialization_work_authority_digest_not_null NOT NULL,
    authority_owner_id uuid CONSTRAINT logical_workflow_materialization_wo_authority_owner_id_not_null NOT NULL,
    authority_generation bigint CONSTRAINT logical_workflow_materialization__authority_generation_not_null NOT NULL,
    authority_claimed_at_ms bigint CONSTRAINT logical_workflow_materializati_authority_claimed_at_ms_not_null NOT NULL,
    authority_expires_at_ms bigint CONSTRAINT logical_workflow_materializati_authority_expires_at_ms_not_null NOT NULL,
    failure_kind text CONSTRAINT logical_workflow_materialization_work_qua_failure_kind_not_null NOT NULL,
    quarantined_at_ms bigint CONSTRAINT logical_workflow_materialization_wor_quarantined_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_materialization_quarantine_shape CHECK (((selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (selection_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (authority_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (selection_generation > 0) AND (authority_generation >= selection_generation) AND (selection_requested_at_ms >= 0) AND ((selection_duration_ms >= 2000) AND (selection_duration_ms <= 300000)) AND (selection_claimed_at_ms >= 0) AND (selection_expires_at_ms = (selection_claimed_at_ms + selection_duration_ms)) AND (octet_length(authority_digest) = 32) AND (authority_claimed_at_ms >= 0) AND (authority_expires_at_ms > authority_claimed_at_ms) AND (failure_kind = ANY (ARRAY['relational_evidence'::text, 'object_evidence'::text, 'payload_evidence'::text, 'generation_exhausted'::text])) AND (quarantined_at_ms >= 0)))
);

CREATE TABLE logical_workflow_materialization_work_selections (
    selection_id uuid CONSTRAINT logical_workflow_materialization_work_sel_selection_id_not_null NOT NULL,
    owner_id uuid CONSTRAINT logical_workflow_materialization_work_selecti_owner_id_not_null NOT NULL,
    requested_at_ms bigint CONSTRAINT logical_workflow_materialization_work__requested_at_ms_not_null NOT NULL,
    duration_ms bigint CONSTRAINT logical_workflow_materialization_work_sele_duration_ms_not_null NOT NULL,
    claimed_at_ms bigint,
    expires_at_ms bigint,
    outcome text CONSTRAINT logical_workflow_materialization_work_selectio_outcome_not_null NOT NULL,
    tenant_id text,
    run_id uuid,
    invocation_id uuid,
    logical_job_id uuid,
    instance_id uuid,
    generation bigint,
    authority_digest bytea,
    CONSTRAINT logical_workflow_materialization_selection_identity CHECK (((selection_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (requested_at_ms >= 0) AND ((duration_ms >= 2000) AND (duration_ms <= 300000)))),
    CONSTRAINT logical_workflow_materialization_selection_shape CHECK (((((outcome = 'selecting'::text) AND (claimed_at_ms IS NULL) AND (expires_at_ms IS NULL) AND (tenant_id IS NULL) AND (run_id IS NULL) AND (invocation_id IS NULL) AND (logical_job_id IS NULL) AND (instance_id IS NULL) AND (generation IS NULL) AND (authority_digest IS NULL)) OR ((outcome = ANY (ARRAY['idle'::text, 'contended'::text, 'claimed'::text, 'quarantined'::text])) AND (claimed_at_ms >= 0) AND (expires_at_ms = (claimed_at_ms + duration_ms)) AND (((outcome = ANY (ARRAY['idle'::text, 'contended'::text])) AND (tenant_id IS NULL) AND (run_id IS NULL) AND (invocation_id IS NULL) AND (logical_job_id IS NULL) AND (instance_id IS NULL) AND (generation IS NULL) AND (authority_digest IS NULL)) OR ((outcome = ANY (ARRAY['claimed'::text, 'quarantined'::text])) AND (tenant_id IS NOT NULL) AND (run_id IS NOT NULL) AND (invocation_id IS NOT NULL) AND (logical_job_id IS NOT NULL) AND (instance_id IS NOT NULL) AND (generation > 0) AND (octet_length(authority_digest) = 32))))) IS TRUE))
);

CREATE TABLE logical_workflow_result_selection_replay_horizons (
    queue_name text CONSTRAINT logical_workflow_result_selection_replay_ho_queue_name_not_null NOT NULL,
    replay_floor_ms bigint CONSTRAINT logical_workflow_result_selection_repl_replay_floor_ms_not_null NOT NULL,
    updated_at_ms bigint CONSTRAINT logical_workflow_result_selection_replay_updated_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_result_selection_replay_horizons_queue CHECK ((queue_name = ANY (ARRAY['instance'::text, 'job'::text]))),
    CONSTRAINT logical_workflow_result_selection_replay_horizons_time CHECK (((replay_floor_ms >= 0) AND (updated_at_ms >= replay_floor_ms)))
);

CREATE TABLE logical_workflow_reusable_call_output_contracts (
    run_id uuid NOT NULL,
    child_invocation_id uuid CONSTRAINT logical_workflow_reusable_call_out_child_invocation_id_not_null NOT NULL,
    mapping_count integer CONSTRAINT logical_workflow_reusable_call_output_co_mapping_count_not_null NOT NULL,
    mapping_digest bytea CONSTRAINT logical_workflow_reusable_call_output_c_mapping_digest_not_null NOT NULL,
    bound_at_ms bigint CONSTRAINT logical_workflow_reusable_call_output_cont_bound_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_reusable_call_output_contracts_count CHECK (((mapping_count >= 0) AND (mapping_count <= 256))),
    CONSTRAINT logical_workflow_reusable_call_output_contracts_digest CHECK ((octet_length(mapping_digest) = 32)),
    CONSTRAINT logical_workflow_reusable_call_output_contracts_time CHECK ((bound_at_ms >= 0))
);

CREATE TABLE logical_workflow_reusable_call_output_mappings (
    run_id uuid NOT NULL,
    child_invocation_id uuid CONSTRAINT logical_workflow_reusable_call_ou_child_invocation_id_not_null1 NOT NULL,
    parent_output_name text CONSTRAINT logical_workflow_reusable_call_outp_parent_output_name_not_null NOT NULL COLLATE pg_catalog."C",
    child_output_name text CONSTRAINT logical_workflow_reusable_call_outpu_child_output_name_not_null NOT NULL COLLATE pg_catalog."C",
    sensitivity text CONSTRAINT logical_workflow_reusable_call_output_mapp_sensitivity_not_null NOT NULL,
    source_order integer CONSTRAINT logical_workflow_reusable_call_output_map_source_order_not_null NOT NULL,
    CONSTRAINT logical_workflow_reusable_call_output_mappings_names CHECK ((((octet_length(parent_output_name) >= 1) AND (octet_length(parent_output_name) <= 256)) AND ((octet_length(child_output_name) >= 1) AND (octet_length(child_output_name) <= 256)) AND (btrim(parent_output_name) = parent_output_name) AND (btrim(child_output_name) = child_output_name) AND (parent_output_name !~ '[[:cntrl:]]'::text) AND (child_output_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT logical_workflow_reusable_call_output_mappings_order CHECK (((source_order >= 0) AND (source_order <= 255))),
    CONSTRAINT logical_workflow_reusable_call_output_mappings_sensitivity CHECK ((sensitivity = ANY (ARRAY['public'::text, 'secret_derived'::text])))
);

CREATE TABLE logical_workflow_reusable_call_publications (
    tenant_id text NOT NULL COLLATE pg_catalog."C",
    repository_id uuid CONSTRAINT logical_workflow_reusable_call_publicati_repository_id_not_null NOT NULL,
    run_id uuid NOT NULL,
    parent_invocation_id uuid CONSTRAINT logical_workflow_reusable_call_pu_parent_invocation_id_not_null NOT NULL,
    caller_logical_job_id uuid CONSTRAINT logical_workflow_reusable_call_p_caller_logical_job_id_not_null NOT NULL,
    caller_instance_id uuid CONSTRAINT logical_workflow_reusable_call_publ_caller_instance_id_not_null NOT NULL,
    child_invocation_id uuid CONSTRAINT logical_workflow_reusable_call_pub_child_invocation_id_not_null NOT NULL,
    operation_id uuid CONSTRAINT logical_workflow_reusable_call_publicatio_operation_id_not_null NOT NULL,
    activation_generation bigint CONSTRAINT logical_workflow_reusable_call_p_activation_generation_not_null NOT NULL,
    activation_input_digest bytea CONSTRAINT logical_workflow_reusable_call_activation_input_digest_not_null NOT NULL,
    condition_matched boolean CONSTRAINT logical_workflow_reusable_call_publi_condition_matched_not_null NOT NULL,
    matrix_digest bytea CONSTRAINT logical_workflow_reusable_call_publicati_matrix_digest_not_null NOT NULL,
    runtime_context_digest bytea CONSTRAINT logical_workflow_reusable_call__runtime_context_digest_not_null NOT NULL,
    runtime_context_object_key text CONSTRAINT logical_workflow_reusable_c_runtime_context_object_key_not_null NOT NULL COLLATE pg_catalog."C",
    runtime_context_size_bytes bigint CONSTRAINT logical_workflow_reusable_c_runtime_context_size_bytes_not_null NOT NULL,
    runtime_context_media_type text CONSTRAINT logical_workflow_reusable_c_runtime_context_media_type_not_null NOT NULL COLLATE pg_catalog."C",
    runtime_context_schema smallint CONSTRAINT logical_workflow_reusable_call__runtime_context_schema_not_null NOT NULL,
    permission_digest bytea CONSTRAINT logical_workflow_reusable_call_publi_permission_digest_not_null NOT NULL,
    output_mapping_count integer CONSTRAINT logical_workflow_reusable_call_pu_output_mapping_count_not_null NOT NULL,
    output_mapping_digest bytea CONSTRAINT logical_workflow_reusable_call_p_output_mapping_digest_not_null NOT NULL,
    publication_digest bytea CONSTRAINT logical_workflow_reusable_call_publ_publication_digest_not_null NOT NULL,
    runtime_policy_revision bigint CONSTRAINT logical_workflow_reusable_call_runtime_policy_revision_not_null NOT NULL,
    runtime_policy_digest bytea CONSTRAINT logical_workflow_reusable_call_p_runtime_policy_digest_not_null NOT NULL,
    authority_profile text CONSTRAINT logical_workflow_reusable_call_publi_authority_profile_not_null NOT NULL COLLATE pg_catalog."C",
    published_at_ms bigint CONSTRAINT logical_workflow_reusable_call_publica_published_at_ms_not_null NOT NULL,
    child_graph_sealed_at_ms bigint,
    CONSTRAINT logical_workflow_reusable_call_publications_context CHECK ((((octet_length(runtime_context_object_key) >= 1) AND (octet_length(runtime_context_object_key) <= 1024)) AND (runtime_context_object_key !~ '[[:cntrl:]]'::text) AND ("left"(runtime_context_object_key, 1) <> '/'::text) AND (runtime_context_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((runtime_context_size_bytes >= 1) AND (runtime_context_size_bytes <= 16777216)) AND (runtime_context_media_type = 'application/vnd.automata.job-runtime-context.protobuf'::text) AND (runtime_context_schema = 1))),
    CONSTRAINT logical_workflow_reusable_call_publications_digests CHECK (((octet_length(activation_input_digest) = 32) AND (octet_length(matrix_digest) = 32) AND (octet_length(runtime_context_digest) = 32) AND (octet_length(permission_digest) = 32) AND (octet_length(output_mapping_digest) = 32) AND (octet_length(publication_digest) = 32) AND (octet_length(runtime_policy_digest) = 32))),
    CONSTRAINT logical_workflow_reusable_call_publications_generation CHECK ((activation_generation = 1)),
    CONSTRAINT logical_workflow_reusable_call_publications_ids_non_nil CHECK (((parent_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (caller_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (caller_instance_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (child_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_reusable_call_publications_policy CHECK (((runtime_policy_revision > 0) AND (authority_profile = 'credential_free'::text) AND ((output_mapping_count >= 0) AND (output_mapping_count <= 256)))),
    CONSTRAINT logical_workflow_reusable_call_publications_time CHECK (((published_at_ms >= 0) AND ((child_graph_sealed_at_ms IS NULL) OR (child_graph_sealed_at_ms = published_at_ms))))
);

CREATE TABLE logical_workflow_reusable_call_result_jobs (
    run_id uuid NOT NULL,
    parent_invocation_id uuid CONSTRAINT logical_workflow_reusable_call_r_parent_invocation_id_not_null1 NOT NULL,
    caller_logical_job_id uuid CONSTRAINT logical_workflow_reusable_call__caller_logical_job_id_not_null1 NOT NULL,
    child_logical_job_id uuid CONSTRAINT logical_workflow_reusable_call_re_child_logical_job_id_not_null NOT NULL,
    source_order integer CONSTRAINT logical_workflow_reusable_call_result_job_source_order_not_null NOT NULL,
    descriptor_digest bytea CONSTRAINT logical_workflow_reusable_call_resu_descriptor_digest_not_null1 NOT NULL,
    outputs_digest bytea CONSTRAINT logical_workflow_reusable_call_result_j_outputs_digest_not_null NOT NULL,
    commit_digest bytea CONSTRAINT logical_workflow_reusable_call_result_jo_commit_digest_not_null NOT NULL,
    effective_conclusion text CONSTRAINT logical_workflow_reusable_call_r_effective_conclusion_not_null1 NOT NULL,
    closure_has_failure boolean CONSTRAINT logical_workflow_reusable_call_res_closure_has_failure_not_null NOT NULL,
    closure_has_cancelled boolean CONSTRAINT logical_workflow_reusable_call_r_closure_has_cancelled_not_null NOT NULL,
    closure_has_skipped boolean CONSTRAINT logical_workflow_reusable_call_res_closure_has_skipped_not_null NOT NULL,
    CONSTRAINT logical_workflow_reusable_call_result_jobs_shape CHECK (((child_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND ((source_order >= 0) AND (source_order <= 1023)) AND (octet_length(descriptor_digest) = 32) AND (octet_length(outputs_digest) = 32) AND (octet_length(commit_digest) = 32) AND (effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text]))))
);

CREATE TABLE logical_workflow_reusable_call_result_outputs (
    run_id uuid NOT NULL,
    parent_invocation_id uuid CONSTRAINT logical_workflow_reusable_call_r_parent_invocation_id_not_null2 NOT NULL,
    caller_logical_job_id uuid CONSTRAINT logical_workflow_reusable_call__caller_logical_job_id_not_null2 NOT NULL,
    callee_output_name text CONSTRAINT logical_workflow_reusable_call_resu_callee_output_name_not_null NOT NULL COLLATE pg_catalog."C",
    sensitivity text CONSTRAINT logical_workflow_reusable_call_result_outp_sensitivity_not_null NOT NULL,
    public_value text,
    source_order integer CONSTRAINT logical_workflow_reusable_call_result_out_source_order_not_null NOT NULL,
    CONSTRAINT logical_workflow_reusable_call_result_outputs_shape CHECK ((((octet_length(callee_output_name) >= 1) AND (octet_length(callee_output_name) <= 256)) AND (btrim(callee_output_name) = callee_output_name) AND (callee_output_name !~ '[[:cntrl:]]'::text) AND ((source_order >= 0) AND (source_order <= 255)) AND (((sensitivity = 'public'::text) AND (public_value IS NOT NULL) AND (octet_length(public_value) <= 2097152)) OR ((sensitivity = 'secret_derived'::text) AND (public_value IS NULL)))))
);

CREATE TABLE logical_workflow_reusable_call_results (
    tenant_id text NOT NULL COLLATE pg_catalog."C",
    repository_id uuid NOT NULL,
    run_id uuid NOT NULL,
    parent_invocation_id uuid CONSTRAINT logical_workflow_reusable_call_re_parent_invocation_id_not_null NOT NULL,
    caller_logical_job_id uuid CONSTRAINT logical_workflow_reusable_call_r_caller_logical_job_id_not_null NOT NULL,
    caller_instance_id uuid CONSTRAINT logical_workflow_reusable_call_resu_caller_instance_id_not_null NOT NULL,
    child_invocation_id uuid CONSTRAINT logical_workflow_reusable_call_res_child_invocation_id_not_null NOT NULL,
    publication_operation_id uuid CONSTRAINT logical_workflow_reusable_cal_publication_operation_id_not_null NOT NULL,
    completion_operation_id uuid CONSTRAINT logical_workflow_reusable_call_completion_operation_id_not_null NOT NULL,
    callee_plan_digest bytea CONSTRAINT logical_workflow_reusable_call_resu_callee_plan_digest_not_null NOT NULL,
    evaluator_schema smallint CONSTRAINT logical_workflow_reusable_call_result_evaluator_schema_not_null NOT NULL,
    child_job_count integer NOT NULL,
    child_jobs_digest bytea CONSTRAINT logical_workflow_reusable_call_resul_child_jobs_digest_not_null NOT NULL,
    workflow_output_evaluation_digest bytea CONSTRAINT logical_workflow_reusable_c_workflow_output_evaluation_not_null NOT NULL,
    descriptor_digest bytea CONSTRAINT logical_workflow_reusable_call_resul_descriptor_digest_not_null NOT NULL,
    effective_conclusion text CONSTRAINT logical_workflow_reusable_call_re_effective_conclusion_not_null NOT NULL,
    output_count integer NOT NULL,
    outputs_digest bytea NOT NULL,
    commit_digest bytea NOT NULL,
    parent_result_descriptor_digest bytea CONSTRAINT logical_workflow_reusable_c_parent_result_descriptor_d_not_null NOT NULL,
    parent_instances_digest bytea CONSTRAINT logical_workflow_reusable_call_parent_instances_digest_not_null NOT NULL,
    parent_prerequisites_digest bytea CONSTRAINT logical_workflow_reusable_c_parent_prerequisites_diges_not_null NOT NULL,
    parent_outputs_digest bytea CONSTRAINT logical_workflow_reusable_call_r_parent_outputs_digest_not_null NOT NULL,
    parent_commit_digest bytea CONSTRAINT logical_workflow_reusable_call_re_parent_commit_digest_not_null NOT NULL,
    completed_at_ms bigint NOT NULL,
    sealed_at_ms bigint,
    CONSTRAINT logical_workflow_reusable_call_results_digests CHECK (((octet_length(callee_plan_digest) = 32) AND (octet_length(child_jobs_digest) = 32) AND (octet_length(workflow_output_evaluation_digest) = 32) AND (octet_length(descriptor_digest) = 32) AND (octet_length(outputs_digest) = 32) AND (octet_length(commit_digest) = 32) AND (octet_length(parent_result_descriptor_digest) = 32) AND (octet_length(parent_instances_digest) = 32) AND (octet_length(parent_prerequisites_digest) = 32) AND (octet_length(parent_outputs_digest) = 32) AND (octet_length(parent_commit_digest) = 32))),
    CONSTRAINT logical_workflow_reusable_call_results_ids_non_nil CHECK (((caller_instance_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (child_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (publication_operation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (completion_operation_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_reusable_call_results_shape CHECK (((evaluator_schema = 1) AND ((child_job_count >= 0) AND (child_job_count <= 4096)) AND ((output_count >= 0) AND (output_count <= 256)) AND (effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text])) AND (completed_at_ms >= 0) AND ((sealed_at_ms IS NULL) OR (sealed_at_ms = completed_at_ms))))
);

CREATE TABLE logical_workflow_reusable_expanded_dependencies (
    run_id uuid NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_reusable_expanded_depen_invocation_id_not_null NOT NULL,
    logical_job_id uuid CONSTRAINT logical_workflow_reusable_expanded_depe_logical_job_id_not_null NOT NULL,
    prerequisite_job_id uuid CONSTRAINT logical_workflow_reusable_expanded_prerequisite_job_id_not_null NOT NULL,
    CONSTRAINT logical_workflow_reusable_expanded_dependencies_no_self CHECK ((logical_job_id <> prerequisite_job_id))
);

CREATE TABLE logical_workflow_reusable_expanded_jobs (
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    logical_key text NOT NULL COLLATE pg_catalog."C",
    source_order integer NOT NULL,
    execution_kind text NOT NULL,
    descriptor_digest bytea CONSTRAINT logical_workflow_reusable_expanded_j_descriptor_digest_not_null NOT NULL,
    environment_requirement_kind text DEFAULT 'unclassified'::text CONSTRAINT logical_workflow_reusable_e_environment_requirement_ki_not_null NOT NULL,
    environment_template_digest bytea,
    secret_reference_names text[] DEFAULT '{}'::text[] CONSTRAINT logical_workflow_reusable_expan_secret_reference_names_not_null NOT NULL,
    variable_reference_names text[] DEFAULT '{}'::text[] CONSTRAINT logical_workflow_reusable_exp_variable_reference_names_not_null NOT NULL,
    credential_requirements_schema smallint DEFAULT 1 CONSTRAINT logical_workflow_reusable_e_credential_requirements_sc_not_null NOT NULL,
    CONSTRAINT reusable_expanded_jobs_credential_schema CHECK ((credential_requirements_schema = 1)),
    CONSTRAINT reusable_expanded_jobs_environment_requirement CHECK ((environment_requirement_kind = ANY (ARRAY['unclassified'::text, 'none'::text, 'environment'::text]))),
    CONSTRAINT reusable_expanded_jobs_environment_shape CHECK (((((environment_requirement_kind = 'environment'::text) AND (octet_length(environment_template_digest) = 32)) OR ((environment_requirement_kind = ANY (ARRAY['unclassified'::text, 'none'::text])) AND (environment_template_digest IS NULL))) IS TRUE)),
    CONSTRAINT reusable_expanded_jobs_reference_limits CHECK (((cardinality(secret_reference_names) <= 256) AND (cardinality(variable_reference_names) <= 256))),
    CONSTRAINT logical_workflow_reusable_expanded_jobs_digest_sha256 CHECK ((octet_length(descriptor_digest) = 32)),
    CONSTRAINT logical_workflow_reusable_expanded_jobs_id_non_nil CHECK ((logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_reusable_expanded_jobs_key_shape CHECK ((((octet_length(logical_key) >= 1) AND (octet_length(logical_key) <= 256)) AND (btrim(logical_key) = logical_key) AND (logical_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT logical_workflow_reusable_expanded_jobs_kind CHECK ((execution_kind = ANY (ARRAY['steps'::text, 'reusable_workflow'::text]))),
    CONSTRAINT logical_workflow_reusable_expanded_jobs_order_bound CHECK (((source_order >= 0) AND (source_order <= 1023)))
);

CREATE TABLE logical_workflow_reusable_input_bindings (
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    input_key text NOT NULL COLLATE pg_catalog."C",
    input_type text NOT NULL,
    binding_kind text NOT NULL,
    value_digest bytea,
    source_order integer NOT NULL,
    CONSTRAINT logical_workflow_reusable_input_bindings_key_shape CHECK ((((octet_length(input_key) >= 1) AND (octet_length(input_key) <= 256)) AND (btrim(input_key) = input_key) AND (input_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT logical_workflow_reusable_input_bindings_kind CHECK ((binding_kind = ANY (ARRAY['caller'::text, 'default'::text, 'implicit_default'::text]))),
    CONSTRAINT logical_workflow_reusable_input_bindings_order CHECK (((source_order >= 0) AND (source_order <= 255))),
    CONSTRAINT logical_workflow_reusable_input_bindings_type CHECK ((input_type = ANY (ARRAY['boolean'::text, 'number'::text, 'string'::text]))),
    CONSTRAINT logical_workflow_reusable_input_bindings_value_shape CHECK (((((binding_kind = 'implicit_default'::text) AND (value_digest IS NULL)) OR ((binding_kind = ANY (ARRAY['caller'::text, 'default'::text])) AND (octet_length(value_digest) = 32))) IS TRUE))
);

CREATE TABLE logical_workflow_reusable_invocation_expansions (
    run_id uuid NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_reusable_invocation_exp_invocation_id_not_null NOT NULL,
    parent_invocation_id uuid,
    caller_logical_job_id uuid,
    catalog_entry_id uuid CONSTRAINT logical_workflow_reusable_invocation__catalog_entry_id_not_null NOT NULL,
    depth smallint NOT NULL,
    call_path text[] CONSTRAINT logical_workflow_reusable_invocation_expansi_call_path_not_null NOT NULL,
    workflow_path text CONSTRAINT logical_workflow_reusable_invocation_exp_workflow_path_not_null NOT NULL COLLATE pg_catalog."C",
    source_digest bytea CONSTRAINT logical_workflow_reusable_invocation_exp_source_digest_not_null NOT NULL,
    plan_digest bytea CONSTRAINT logical_workflow_reusable_invocation_expan_plan_digest_not_null NOT NULL,
    call_reference_digest bytea,
    input_bindings_digest bytea CONSTRAINT logical_workflow_reusable_invoca_input_bindings_digest_not_null NOT NULL,
    secret_bindings_digest bytea CONSTRAINT logical_workflow_reusable_invoc_secret_bindings_digest_not_null NOT NULL,
    output_contract_digest bytea CONSTRAINT logical_workflow_reusable_invoc_output_contract_digest_not_null NOT NULL,
    permission_digest bytea CONSTRAINT logical_workflow_reusable_invocation_permission_digest_not_null NOT NULL,
    descriptor_digest bytea CONSTRAINT logical_workflow_reusable_invocation_descriptor_digest_not_null NOT NULL,
    input_binding_count integer CONSTRAINT logical_workflow_reusable_invocati_input_binding_count_not_null NOT NULL,
    secret_binding_count integer CONSTRAINT logical_workflow_reusable_invocat_secret_binding_count_not_null NOT NULL,
    output_count integer CONSTRAINT logical_workflow_reusable_invocation_expa_output_count_not_null NOT NULL,
    permission_grant_count integer CONSTRAINT logical_workflow_reusable_invoc_permission_grant_count_not_null NOT NULL,
    dependency_count integer CONSTRAINT logical_workflow_reusable_invocation__dependency_count_not_null NOT NULL,
    created_at_ms bigint CONSTRAINT logical_workflow_reusable_invocation_exp_created_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_reusable_expansions_caller_non_nil CHECK (((caller_logical_job_id IS NULL) OR (caller_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_reusable_expansions_contract_counts CHECK ((((input_binding_count >= 0) AND (input_binding_count <= 256)) AND ((secret_binding_count >= 0) AND (secret_binding_count <= 256)) AND ((output_count >= 0) AND (output_count <= 256)) AND ((permission_grant_count >= 0) AND (permission_grant_count <= 256)) AND ((dependency_count >= 0) AND (dependency_count <= 1047552)))),
    CONSTRAINT logical_workflow_reusable_expansions_depth CHECK (((depth >= 0) AND (depth <= 9))),
    CONSTRAINT logical_workflow_reusable_expansions_digests_sha256 CHECK (((octet_length(source_digest) = 32) AND (octet_length(plan_digest) = 32) AND (octet_length(input_bindings_digest) = 32) AND (octet_length(secret_bindings_digest) = 32) AND (octet_length(output_contract_digest) = 32) AND (octet_length(permission_digest) = 32) AND (octet_length(descriptor_digest) = 32))),
    CONSTRAINT logical_workflow_reusable_expansions_id_non_nil CHECK ((invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_reusable_expansions_parent_non_nil CHECK (((parent_invocation_id IS NULL) OR (parent_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_reusable_expansions_path_shape CHECK (((cardinality(call_path) = (depth + 1)) AND (call_path[(depth + 1)] = workflow_path) AND (array_position(call_path, NULL::text) IS NULL))),
    CONSTRAINT logical_workflow_reusable_expansions_root_child_shape CHECK (((((depth = 0) AND (parent_invocation_id IS NULL) AND (caller_logical_job_id IS NULL) AND (call_reference_digest IS NULL)) OR ((depth > 0) AND (parent_invocation_id IS NOT NULL) AND (caller_logical_job_id IS NOT NULL) AND (octet_length(call_reference_digest) = 32))) IS TRUE)),
    CONSTRAINT logical_workflow_reusable_expansions_time CHECK ((created_at_ms >= 0))
);

CREATE TABLE logical_workflow_reusable_outputs (
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    output_key text NOT NULL COLLATE pg_catalog."C",
    sensitivity text NOT NULL,
    source_order integer NOT NULL,
    CONSTRAINT logical_workflow_reusable_outputs_key_shape CHECK ((((octet_length(output_key) >= 1) AND (octet_length(output_key) <= 256)) AND (btrim(output_key) = output_key) AND (output_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT logical_workflow_reusable_outputs_order CHECK (((source_order >= 0) AND (source_order <= 255))),
    CONSTRAINT logical_workflow_reusable_outputs_sensitivity CHECK ((sensitivity = ANY (ARRAY['public'::text, 'secret_derived'::text])))
);

CREATE TABLE logical_workflow_reusable_permission_grants (
    run_id uuid NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_reusable_permission_gra_invocation_id_not_null NOT NULL,
    permission_name text CONSTRAINT logical_workflow_reusable_permission_g_permission_name_not_null NOT NULL COLLATE pg_catalog."C",
    permission_level text CONSTRAINT logical_workflow_reusable_permission__permission_level_not_null NOT NULL,
    CONSTRAINT logical_workflow_reusable_permission_grants_level CHECK ((permission_level = ANY (ARRAY['none'::text, 'read'::text, 'write'::text]))),
    CONSTRAINT logical_workflow_reusable_permission_grants_name_shape CHECK ((((octet_length(permission_name) >= 1) AND (octet_length(permission_name) <= 256)) AND (btrim(permission_name) = permission_name) AND (permission_name !~ '[[:cntrl:]]'::text)))
);

CREATE TABLE logical_workflow_reusable_permission_snapshots (
    run_id uuid NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_reusable_permission_sna_invocation_id_not_null NOT NULL,
    default_level text CONSTRAINT logical_workflow_reusable_permission_sna_default_level_not_null NOT NULL,
    permission_digest bytea CONSTRAINT logical_workflow_reusable_permission_permission_digest_not_null NOT NULL,
    CONSTRAINT logical_workflow_reusable_permission_snapshots_digest CHECK ((octet_length(permission_digest) = 32)),
    CONSTRAINT logical_workflow_reusable_permission_snapshots_level CHECK ((default_level = ANY (ARRAY['none'::text, 'read'::text, 'write'::text])))
);

CREATE TABLE logical_workflow_reusable_secret_bindings (
    run_id uuid NOT NULL,
    invocation_id uuid CONSTRAINT logical_workflow_reusable_secret_binding_invocation_id_not_null NOT NULL,
    target_name text NOT NULL COLLATE pg_catalog."C",
    source_name text NOT NULL COLLATE pg_catalog."C",
    source_order integer NOT NULL,
    CONSTRAINT logical_workflow_reusable_secret_bindings_name_only CHECK ((((octet_length(target_name) >= 1) AND (octet_length(target_name) <= 256)) AND ((octet_length(source_name) >= 1) AND (octet_length(source_name) <= 256)) AND (btrim(target_name) = target_name) AND (btrim(source_name) = source_name) AND (target_name !~ '[[:cntrl:]]'::text) AND (source_name !~ '[[:cntrl:]]'::text))),
    CONSTRAINT logical_workflow_reusable_secret_bindings_order CHECK (((source_order >= 0) AND (source_order <= 255)))
);

CREATE TABLE logical_workflow_reusable_workflow_catalog (
    run_id uuid NOT NULL,
    catalog_entry_id uuid CONSTRAINT logical_workflow_reusable_workflow_ca_catalog_entry_id_not_null NOT NULL,
    workflow_path text CONSTRAINT logical_workflow_reusable_workflow_catal_workflow_path_not_null NOT NULL COLLATE pg_catalog."C",
    source_revision text CONSTRAINT logical_workflow_reusable_workflow_cat_source_revision_not_null NOT NULL COLLATE pg_catalog."C",
    source_digest bytea CONSTRAINT logical_workflow_reusable_workflow_catal_source_digest_not_null NOT NULL,
    source_object_key text CONSTRAINT logical_workflow_reusable_workflow_c_source_object_key_not_null NOT NULL COLLATE pg_catalog."C",
    source_size_bytes bigint CONSTRAINT logical_workflow_reusable_workflow_c_source_size_bytes_not_null NOT NULL,
    source_media_type text CONSTRAINT logical_workflow_reusable_workflow_c_source_media_type_not_null NOT NULL COLLATE pg_catalog."C",
    plan_digest bytea NOT NULL,
    plan_object_key text CONSTRAINT logical_workflow_reusable_workflow_cat_plan_object_key_not_null NOT NULL COLLATE pg_catalog."C",
    plan_size_bytes bigint CONSTRAINT logical_workflow_reusable_workflow_cat_plan_size_bytes_not_null NOT NULL,
    plan_media_type text CONSTRAINT logical_workflow_reusable_workflow_cat_plan_media_type_not_null NOT NULL COLLATE pg_catalog."C",
    plan_schema smallint NOT NULL,
    invocation_contract_digest bytea,
    descriptor_digest bytea CONSTRAINT logical_workflow_reusable_workflow_c_descriptor_digest_not_null NOT NULL,
    logical_job_count integer CONSTRAINT logical_workflow_reusable_workflow_c_logical_job_count_not_null NOT NULL,
    reusable_call_count integer CONSTRAINT logical_workflow_reusable_workflow_reusable_call_count_not_null NOT NULL,
    created_at_ms bigint CONSTRAINT logical_workflow_reusable_workflow_catal_created_at_ms_not_null NOT NULL,
    CONSTRAINT logical_workflow_reusable_catalog_digests_sha256 CHECK (((octet_length(source_digest) = 32) AND (octet_length(plan_digest) = 32) AND (octet_length(descriptor_digest) = 32) AND ((invocation_contract_digest IS NULL) OR (octet_length(invocation_contract_digest) = 32)))),
    CONSTRAINT logical_workflow_reusable_catalog_id_non_nil CHECK ((catalog_entry_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_reusable_catalog_job_bounds CHECK ((((logical_job_count >= 1) AND (logical_job_count <= 1024)) AND ((reusable_call_count >= 0) AND (reusable_call_count <= logical_job_count)))),
    CONSTRAINT logical_workflow_reusable_catalog_path_canonical CHECK ((((octet_length(workflow_path) >= 19) AND (octet_length(workflow_path) <= 1024)) AND (workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'::text) AND (workflow_path !~ '[[:cntrl:]]'::text) AND (POSITION(('\'::text) IN (workflow_path)) = 0))),
    CONSTRAINT logical_workflow_reusable_catalog_plan_object CHECK ((((octet_length(plan_object_key) >= 1) AND (octet_length(plan_object_key) <= 1024)) AND (plan_object_key !~ '[[:cntrl:]]'::text) AND ("left"(plan_object_key, 1) <> '/'::text) AND (plan_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((plan_size_bytes >= 1) AND (plan_size_bytes <= 16777216)) AND (plan_media_type = 'application/vnd.automata.workflow-plan+json'::text) AND (plan_schema = 1))),
    CONSTRAINT logical_workflow_reusable_catalog_revision_shape CHECK ((source_revision ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'::text)),
    CONSTRAINT logical_workflow_reusable_catalog_source_object CHECK ((((octet_length(source_object_key) >= 1) AND (octet_length(source_object_key) <= 1024)) AND (source_object_key !~ '[[:cntrl:]]'::text) AND ("left"(source_object_key, 1) <> '/'::text) AND (source_object_key !~ '(^|/)\.\.(/|$)'::text) AND ((source_size_bytes >= 1) AND (source_size_bytes <= 16777216)) AND ((octet_length(source_media_type) >= 3) AND (octet_length(source_media_type) <= 128)) AND (source_media_type ~~ '%/%'::text) AND (source_media_type !~ '[[:space:][:cntrl:];]'::text))),
    CONSTRAINT logical_workflow_reusable_catalog_time CHECK ((created_at_ms >= 0))
);

CREATE TABLE logical_workflow_reusable_workflow_runs (
    tenant_id text NOT NULL COLLATE pg_catalog."C",
    repository_id uuid NOT NULL,
    run_id uuid NOT NULL,
    root_invocation_id uuid CONSTRAINT logical_workflow_reusable_workflow__root_invocation_id_not_null NOT NULL,
    reusable_schema smallint DEFAULT 1 CONSTRAINT logical_workflow_reusable_workflow_run_reusable_schema_not_null NOT NULL,
    expansion_digest bytea CONSTRAINT logical_workflow_reusable_workflow_ru_expansion_digest_not_null NOT NULL,
    catalog_entry_count integer CONSTRAINT logical_workflow_reusable_workflow_catalog_entry_count_not_null NOT NULL,
    invocation_count integer CONSTRAINT logical_workflow_reusable_workflow_ru_invocation_count_not_null NOT NULL,
    expanded_job_count integer CONSTRAINT logical_workflow_reusable_workflow__expanded_job_count_not_null NOT NULL,
    maximum_depth smallint NOT NULL,
    planned_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_reusable_runs_catalog_limit CHECK (((catalog_entry_count >= 1) AND (catalog_entry_count <= 50))),
    CONSTRAINT logical_workflow_reusable_runs_depth_limit CHECK (((maximum_depth >= 0) AND (maximum_depth <= 9))),
    CONSTRAINT logical_workflow_reusable_runs_digest_sha256 CHECK ((octet_length(expansion_digest) = 32)),
    CONSTRAINT logical_workflow_reusable_runs_invocation_limit CHECK (((invocation_count >= 1) AND (invocation_count <= 256))),
    CONSTRAINT logical_workflow_reusable_runs_job_limit CHECK (((expanded_job_count >= 1) AND (expanded_job_count <= 4096))),
    CONSTRAINT logical_workflow_reusable_runs_root_non_nil CHECK ((root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT logical_workflow_reusable_runs_schema_exact CHECK ((reusable_schema = 1)),
    CONSTRAINT logical_workflow_reusable_runs_time CHECK ((planned_at_ms >= 0))
);

CREATE TABLE logical_workflow_run_result_claims (
    run_id uuid NOT NULL,
    root_invocation_id uuid NOT NULL,
    descriptor_digest bytea NOT NULL,
    state text NOT NULL,
    owner_id uuid NOT NULL,
    generation bigint NOT NULL,
    claimed_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_run_result_claims_digest CHECK ((octet_length(descriptor_digest) = 32)),
    CONSTRAINT logical_workflow_run_result_claims_generation CHECK ((generation > 0)),
    CONSTRAINT logical_workflow_run_result_claims_interval CHECK (((claimed_at_ms >= 0) AND (expires_at_ms > claimed_at_ms) AND ((expires_at_ms - claimed_at_ms) <= 900000) AND (created_at_ms <= claimed_at_ms) AND (updated_at_ms >= claimed_at_ms))),
    CONSTRAINT logical_workflow_run_result_claims_non_nil CHECK (((run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_run_result_claims_state CHECK ((state = ANY (ARRAY['aggregating'::text, 'finalized'::text])))
);

CREATE TABLE logical_workflow_run_result_jobs (
    run_id uuid NOT NULL,
    root_invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    logical_key text NOT NULL COLLATE pg_catalog."C",
    source_order integer NOT NULL,
    descriptor_digest bytea NOT NULL,
    effective_conclusion text NOT NULL,
    closure_has_failure boolean NOT NULL,
    closure_has_cancelled boolean NOT NULL,
    closure_has_skipped boolean NOT NULL,
    instance_count integer NOT NULL,
    instances_digest bytea NOT NULL,
    prerequisite_count integer NOT NULL,
    prerequisites_digest bytea NOT NULL,
    output_count integer NOT NULL,
    outputs_digest bytea NOT NULL,
    job_commit_digest bytea NOT NULL,
    job_finalized_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_run_result_jobs_conclusion CHECK (((effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text])) AND ((effective_conclusion <> ALL (ARRAY['failure'::text, 'timed_out'::text])) OR closure_has_failure) AND ((effective_conclusion <> 'cancelled'::text) OR closure_has_cancelled) AND ((effective_conclusion <> 'skipped'::text) OR closure_has_skipped))),
    CONSTRAINT logical_workflow_run_result_jobs_counts CHECK ((((instance_count >= 0) AND (instance_count <= 256)) AND ((prerequisite_count >= 0) AND (prerequisite_count <= 128)) AND ((output_count >= 0) AND (output_count <= 256)) AND (job_finalized_at_ms >= 0))),
    CONSTRAINT logical_workflow_run_result_jobs_digest_shape CHECK (((octet_length(descriptor_digest) = 32) AND (octet_length(instances_digest) = 32) AND (octet_length(prerequisites_digest) = 32) AND (octet_length(outputs_digest) = 32) AND (octet_length(job_commit_digest) = 32))),
    CONSTRAINT logical_workflow_run_result_jobs_key_shape CHECK ((((octet_length(logical_key) >= 1) AND (octet_length(logical_key) <= 256)) AND (btrim(logical_key) = logical_key) AND (logical_key !~ '[[:cntrl:]]'::text) AND ((source_order >= 0) AND (source_order <= 1023)))),
    CONSTRAINT logical_workflow_run_result_jobs_non_nil CHECK ((logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid))
);

CREATE TABLE logical_workflow_run_results (
    run_id uuid NOT NULL,
    root_invocation_id uuid NOT NULL,
    descriptor_digest bytea NOT NULL,
    admission_digest bytea NOT NULL,
    marker_state text NOT NULL,
    marker_revision bigint NOT NULL,
    marker_updated_at_ms bigint NOT NULL,
    invocation_state text NOT NULL,
    invocation_revision bigint NOT NULL,
    invocation_updated_at_ms bigint NOT NULL,
    workflow_status text NOT NULL,
    workflow_updated_at_ms bigint NOT NULL,
    job_count integer NOT NULL,
    evidence_digest bytea NOT NULL,
    effective_conclusion text NOT NULL,
    commit_digest bytea NOT NULL,
    claim_owner_id uuid NOT NULL,
    claim_generation bigint NOT NULL,
    claim_started_at_ms bigint NOT NULL,
    claim_expires_at_ms bigint NOT NULL,
    finalized_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_run_results_claim_shape CHECK (((claim_generation > 0) AND (claim_started_at_ms >= 0) AND (claim_expires_at_ms > claim_started_at_ms) AND ((claim_expires_at_ms - claim_started_at_ms) <= 900000) AND (finalized_at_ms >= claim_started_at_ms) AND (finalized_at_ms < claim_expires_at_ms))),
    CONSTRAINT logical_workflow_run_results_conclusion CHECK ((effective_conclusion = ANY (ARRAY['success'::text, 'failure'::text, 'cancelled'::text, 'timed_out'::text, 'skipped'::text]))),
    CONSTRAINT logical_workflow_run_results_digest_shape CHECK (((octet_length(descriptor_digest) = 32) AND (octet_length(admission_digest) = 32) AND (octet_length(evidence_digest) = 32) AND (octet_length(commit_digest) = 32))),
    CONSTRAINT logical_workflow_run_results_job_count CHECK (((job_count >= 1) AND (job_count <= 1024))),
    CONSTRAINT logical_workflow_run_results_non_nil CHECK (((run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT logical_workflow_run_results_open_shape CHECK (((marker_state = ANY (ARRAY['pending'::text, 'active'::text])) AND (invocation_state = ANY (ARRAY['pending'::text, 'active'::text])) AND (workflow_status = ANY (ARRAY['queued'::text, 'in_progress'::text, 'cancelled'::text])) AND (marker_revision > 0) AND (marker_revision < '9223372036854775807'::bigint) AND (invocation_revision > 0) AND (invocation_revision < '9223372036854775807'::bigint) AND (marker_updated_at_ms >= 0) AND (invocation_updated_at_ms >= 0) AND (workflow_updated_at_ms >= 0)))
);

CREATE TABLE logical_workflow_runtime_policy_pins (
    run_id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    policy_digest bytea NOT NULL,
    pinned_at_ms bigint NOT NULL,
    CONSTRAINT logical_workflow_runtime_policy_pins_shape CHECK (((run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (policy_revision > 0) AND (octet_length(policy_digest) = 32) AND (pinned_at_ms >= 0)))
);

CREATE TABLE logical_workflow_work_selection_replay_horizons (
    queue_name text CONSTRAINT logical_workflow_work_selection_replay_hori_queue_name_not_null NOT NULL,
    replay_floor_ms bigint CONSTRAINT logical_workflow_work_selection_replay_replay_floor_ms_not_null NOT NULL,
    updated_at_ms bigint CONSTRAINT logical_workflow_work_selection_replay_h_updated_at_ms_not_null NOT NULL,
    cursor_ready_at_ms bigint,
    cursor_run_id uuid,
    cursor_invocation_id uuid,
    cursor_source_order integer,
    cursor_matrix_index integer,
    cursor_target_id uuid,
    CONSTRAINT logical_workflow_work_selection_horizon_cursor CHECK ((((cursor_ready_at_ms IS NULL) AND (cursor_run_id IS NULL) AND (cursor_invocation_id IS NULL) AND (cursor_source_order IS NULL) AND (cursor_matrix_index IS NULL) AND (cursor_target_id IS NULL)) OR ((cursor_ready_at_ms >= 0) AND (cursor_run_id IS NOT NULL) AND (cursor_invocation_id IS NOT NULL) AND ((cursor_source_order >= 0) AND (cursor_source_order <= 1023)) AND (cursor_target_id IS NOT NULL) AND (((queue_name = 'activation'::text) AND (cursor_matrix_index IS NULL)) OR ((queue_name = 'materialization'::text) AND ((cursor_matrix_index >= 0) AND (cursor_matrix_index <= 255))))))),
    CONSTRAINT logical_workflow_work_selection_horizon_queue CHECK ((queue_name = ANY (ARRAY['activation'::text, 'materialization'::text]))),
    CONSTRAINT logical_workflow_work_selection_horizon_time CHECK (((replay_floor_ms >= 0) AND (updated_at_ms >= replay_floor_ms)))
);

CREATE TABLE workflow_rerun_attempt_jobs (
    run_id uuid NOT NULL,
    source_run_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    source_logical_job_id uuid NOT NULL,
    selected boolean NOT NULL,
    CONSTRAINT workflow_rerun_attempt_jobs_ids_non_nil CHECK (((source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (source_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid)))
);

CREATE TABLE workflow_rerun_audit_evidence (
    run_id uuid NOT NULL,
    tenant_id text NOT NULL,
    operation_id uuid NOT NULL,
    event_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    recorded_at_ms bigint NOT NULL,
    CONSTRAINT workflow_rerun_audit_evidence_shape CHECK (((run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (event_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (octet_length(request_digest) = 32) AND (recorded_at_ms >= 0)))
);

CREATE TABLE workflow_run_number_counters (
    workflow_id uuid NOT NULL,
    next_run_number bigint NOT NULL,
    CONSTRAINT workflow_run_number_counters_positive CHECK ((next_run_number > 1))
);

ALTER TABLE workflow_runs ALTER COLUMN run_id_alias ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME workflow_runs_run_id_alias_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    MAXVALUE 9007199254740991
    CACHE 1
);

CREATE TABLE workflow_runtime_policy_current (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    policy_digest bytea NOT NULL,
    activated_at_ms bigint NOT NULL,
    CONSTRAINT workflow_runtime_policy_current_shape CHECK (((policy_revision > 0) AND (octet_length(policy_digest) = 32) AND (activated_at_ms >= 0)))
);

CREATE TABLE workflow_runtime_policy_features (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    selector text NOT NULL COLLATE pg_catalog."C",
    feature text NOT NULL COLLATE pg_catalog."C",
    CONSTRAINT workflow_runtime_policy_features_shape CHECK ((((octet_length(feature) >= 1) AND (octet_length(feature) <= 128)) AND
CASE
    WHEN (feature ~ '^[a-z]([a-z0-9-]*[a-z0-9])?(\.[a-z]([a-z0-9-]*[a-z0-9])?)*/[a-z]([a-z0-9-]*[a-z0-9])?@v[1-9][0-9]{0,4}$'::text) THEN ((("substring"(feature, '@v([1-9][0-9]{0,4})$'::text))::integer >= 1) AND (("substring"(feature, '@v([1-9][0-9]{0,4})$'::text))::integer <= 65535))
    ELSE false
END))
);

CREATE TABLE workflow_runtime_policy_mappings (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    selector text NOT NULL COLLATE pg_catalog."C",
    environment_profile_id text CONSTRAINT workflow_runtime_policy_mapping_environment_profile_id_not_null NOT NULL COLLATE pg_catalog."C",
    environment_profile_digest bytea CONSTRAINT workflow_runtime_policy_map_environment_profile_digest_not_null NOT NULL,
    operating_system text NOT NULL,
    architecture text NOT NULL,
    feature_count integer NOT NULL,
    CONSTRAINT workflow_runtime_policy_mappings_environment CHECK ((((octet_length(environment_profile_id) >= 3) AND (octet_length(environment_profile_id) <= 128)) AND (environment_profile_id ~ '^[a-z]([a-z0-9-]*[a-z0-9])?(\.[a-z]([a-z0-9-]*[a-z0-9])?)*/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'::text) AND (octet_length(environment_profile_digest) = 32))),
    CONSTRAINT workflow_runtime_policy_mappings_feature_count CHECK (((feature_count >= 0) AND (feature_count <= 64))),
    CONSTRAINT workflow_runtime_policy_mappings_platform CHECK (((operating_system = ANY (ARRAY['linux'::text, 'windows'::text, 'macos'::text])) AND (architecture = ANY (ARRAY['x86_64'::text, 'aarch64'::text])))),
    CONSTRAINT workflow_runtime_policy_mappings_selector CHECK ((((char_length(selector) >= 1) AND (char_length(selector) <= 256)) AND (selector = lower(selector)) AND (btrim(selector) = selector) AND (selector ~ '^[ -~]+$'::text)))
);

CREATE TABLE workflow_runtime_policy_revisions (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    policy_digest bytea NOT NULL,
    canonical_policy bytea NOT NULL,
    policy_schema smallint NOT NULL,
    workspace_root text NOT NULL COLLATE pg_catalog."C",
    workspace_derivation_version smallint CONSTRAINT workflow_runtime_policy_rev_workspace_derivation_versi_not_null NOT NULL,
    mapping_count integer NOT NULL,
    state text NOT NULL,
    registered_at_ms bigint NOT NULL,
    sealed_at_ms bigint,
    resource_policy_canonical bytea CONSTRAINT workflow_runtime_policy_revi_resource_policy_canonical_not_null NOT NULL,
    permission_policy_canonical bytea CONSTRAINT workflow_runtime_policy_rev_permission_policy_canonica_not_null NOT NULL,
    CONSTRAINT workflow_runtime_policy_revisions_canonical_size CHECK (((octet_length(canonical_policy) >= 1) AND (octet_length(canonical_policy) <= 65536))),
    CONSTRAINT workflow_runtime_policy_revisions_identity CHECK (((repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (policy_revision > 0) AND (octet_length(policy_digest) = 32) AND (policy_schema = 1) AND ((octet_length(permission_policy_canonical) >= 1) AND (octet_length(permission_policy_canonical) <= 32768)) AND ((octet_length(resource_policy_canonical) >= 1) AND (octet_length(resource_policy_canonical) <= 8192)))),
    CONSTRAINT workflow_runtime_policy_revisions_lifecycle CHECK (((((state = 'staging'::text) AND (sealed_at_ms IS NULL)) OR ((state = 'sealed'::text) AND (sealed_at_ms = registered_at_ms))) IS TRUE)),
    CONSTRAINT workflow_runtime_policy_revisions_mapping_count CHECK (((mapping_count >= 1) AND (mapping_count <= 64))),
    CONSTRAINT workflow_runtime_policy_revisions_time CHECK ((registered_at_ms >= 0)),
    CONSTRAINT workflow_runtime_policy_revisions_workspace CHECK (((workspace_derivation_version = 1) AND (workspace_root = '/__w'::text)))
);

CREATE TABLE workflow_snapshots (
    id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    source_digest bytea NOT NULL,
    source_object_key text NOT NULL,
    frontend_schema smallint NOT NULL,
    created_at_ms bigint NOT NULL,
    admission_epoch integer DEFAULT 1 NOT NULL,
    source_size_bytes bigint,
    source_media_type text,
    CONSTRAINT workflow_snapshots_admission_epoch CHECK ((admission_epoch = 1)),
    CONSTRAINT workflow_snapshots_current_object_metadata CHECK (((source_size_bytes >= 1) AND (source_size_bytes <= 16777216) AND ((octet_length(source_media_type) >= 3) AND (octet_length(source_media_type) <= 128)) AND (source_media_type ~~ '%/%'::text) AND (source_media_type !~ '[[:space:][:cntrl:];]'::text))),
    CONSTRAINT workflow_snapshots_object_key_nonempty CHECK ((length(source_object_key) > 0)),
    CONSTRAINT workflow_snapshots_schema_positive CHECK ((frontend_schema > 0)),
    CONSTRAINT workflow_snapshots_sha256 CHECK ((octet_length(source_digest) = 32))
);

CREATE TABLE workflow_variable_versions (
    tenant_id text NOT NULL,
    id uuid NOT NULL,
    variable_id uuid NOT NULL,
    version_number bigint NOT NULL,
    value_object_key text NOT NULL,
    value_ciphertext_sha256 bytea NOT NULL,
    value_size_bytes bigint NOT NULL,
    value_media_type text NOT NULL,
    envelope_schema smallint NOT NULL,
    created_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    CONSTRAINT workflow_variable_versions_ciphertext_digest CHECK ((octet_length(value_ciphertext_sha256) = 32)),
    CONSTRAINT workflow_variable_versions_created_at CHECK ((created_at_ms >= 0)),
    CONSTRAINT workflow_variable_versions_media_type CHECK (((value_media_type = 'application/vnd.automata.encrypted-variable-value'::text) AND (envelope_schema = 1))),
    CONSTRAINT workflow_variable_versions_non_nil CHECK (((id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (id <> variable_id))),
    CONSTRAINT workflow_variable_versions_number_positive CHECK ((version_number > 0)),
    CONSTRAINT workflow_variable_versions_object_key CHECK ((((octet_length(value_object_key) >= 1) AND (octet_length(value_object_key) <= 1024)) AND (value_object_key !~ '[[:cntrl:]]'::text) AND ("left"(value_object_key, 1) <> '/'::text) AND (value_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT workflow_variable_versions_size CHECK (((value_size_bytes >= 1) AND (value_size_bytes <= 1048576)))
);

CREATE TABLE workflow_variables (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    environment_id uuid,
    id uuid NOT NULL,
    scope_kind text NOT NULL,
    canonical_name text NOT NULL,
    current_version_id uuid,
    current_version_number bigint,
    status text DEFAULT 'provisioning'::text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_by_principal_id uuid,
    updated_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT workflow_variables_head_shape CHECK (((((status = 'provisioning'::text) AND (current_version_id IS NULL) AND (current_version_number IS NULL)) OR ((status = ANY (ARRAY['active'::text, 'disabled'::text, 'deleted'::text])) AND (current_version_id IS NOT NULL) AND (current_version_number > 0))) IS TRUE)),
    CONSTRAINT workflow_variables_name CHECK ((((octet_length(canonical_name) >= 1) AND (octet_length(canonical_name) <= 255)) AND (canonical_name ~ '^[A-Z_][A-Z0-9_]*$'::text) AND (canonical_name !~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'::text))),
    CONSTRAINT workflow_variables_non_nil CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT workflow_variables_revision_positive CHECK ((revision > 0)),
    CONSTRAINT workflow_variables_scope CHECK ((((scope_kind = 'repository'::text) AND (environment_id IS NULL)) OR ((scope_kind = 'environment'::text) AND (environment_id IS NOT NULL)))),
    CONSTRAINT workflow_variables_status CHECK ((status = ANY (ARRAY['provisioning'::text, 'active'::text, 'disabled'::text, 'deleted'::text]))),
    CONSTRAINT workflow_variables_time_monotonic CHECK (((created_at_ms >= 0) AND (updated_at_ms >= created_at_ms)))
);
