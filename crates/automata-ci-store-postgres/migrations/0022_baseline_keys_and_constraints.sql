ALTER TABLE ONLY attempt_cancellation_intents
    ADD CONSTRAINT attempt_cancellation_intents_attempt_operation_unique UNIQUE (attempt_id, operation_id);

ALTER TABLE ONLY attempt_cancellation_intents
    ADD CONSTRAINT attempt_cancellation_intents_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY attempt_cancellation_intents
    ADD CONSTRAINT attempt_cancellation_intents_pkey PRIMARY KEY (attempt_id);

ALTER TABLE ONLY attempt_log_segments
    ADD CONSTRAINT attempt_log_segments_last_unique UNIQUE (stream_id, last_sequence);

ALTER TABLE ONLY attempt_log_segments
    ADD CONSTRAINT attempt_log_segments_operation_unique UNIQUE (stream_id, operation_id);

ALTER TABLE ONLY attempt_log_segments
    ADD CONSTRAINT attempt_log_segments_primary_key PRIMARY KEY (stream_id, first_sequence);

ALTER TABLE ONLY attempt_log_streams
    ADD CONSTRAINT attempt_log_streams_attempt_id_unique UNIQUE (attempt_id, id);

ALTER TABLE ONLY attempt_log_streams
    ADD CONSTRAINT attempt_log_streams_operation_unique UNIQUE (runner_session_id, operation_id);

ALTER TABLE ONLY attempt_log_streams
    ADD CONSTRAINT attempt_log_streams_pkey PRIMARY KEY (id);

ALTER TABLE ONLY attempt_terminal_results
    ADD CONSTRAINT attempt_terminal_results_operation_unique UNIQUE (runner_session_id, operation_id);

ALTER TABLE ONLY attempt_terminal_results
    ADD CONSTRAINT attempt_terminal_results_pkey PRIMARY KEY (attempt_id);

ALTER TABLE ONLY job_attempts
    ADD CONSTRAINT attempts_job_id_artifact_unique UNIQUE (job_id, id);

ALTER TABLE ONLY automata_cluster_compatibility
    ADD CONSTRAINT automata_cluster_compatibility_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY concurrency_group_pending_runs
    ADD CONSTRAINT concurrency_group_pending_runs_primary_key PRIMARY KEY (repository_id, normalized_key, run_id);

ALTER TABLE ONLY concurrency_group_pending_runs
    ADD CONSTRAINT concurrency_group_pending_runs_run_unique UNIQUE (run_id);

ALTER TABLE ONLY concurrency_group_pending_runs
    ADD CONSTRAINT concurrency_group_pending_runs_sequence_unique UNIQUE (queue_sequence);

ALTER TABLE ONLY concurrency_groups
    ADD CONSTRAINT concurrency_groups_primary_key PRIMARY KEY (repository_id, normalized_key);

ALTER TABLE ONLY github_actions_cache_blocks
    ADD CONSTRAINT gha_cache_blocks_primary_key PRIMARY KEY (entry_id, block_id);

ALTER TABLE ONLY github_actions_cache_entries
    ADD CONSTRAINT gha_cache_exact_entry_unique UNIQUE (repository_id, cache_ref, cache_key, cache_version);

ALTER TABLE ONLY github_actions_cache_block_commits
    ADD CONSTRAINT github_actions_cache_block_commits_pkey PRIMARY KEY (entry_id);

ALTER TABLE ONLY github_actions_cache_entries
    ADD CONSTRAINT github_actions_cache_entries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY github_actions_cache_entries
    ADD CONSTRAINT github_actions_cache_entries_protocol_entry_id_key UNIQUE (protocol_entry_id);

ALTER TABLE ONLY github_check_projection_outbox
    ADD CONSTRAINT github_check_projection_outbox_pkey PRIMARY KEY (subject_id);

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_delivery_key_unique UNIQUE (provider_delivery_id, subject_key);

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_external_id_unique UNIQUE (provider_connection_id, external_id);

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_pkey PRIMARY KEY (id);

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_tenant_id_unique UNIQUE (tenant_id, id);

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_workflow_rerun_identity_unique UNIQUE (tenant_id, repository_id, provider_connection_id, workflow_rerun_run_id, id);

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_workflow_rerun_unique UNIQUE (workflow_rerun_run_id, subject_key);

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_job_attempt_unique UNIQUE (job_attempt_id);

ALTER TABLE ONLY github_membership_snapshots
    ADD CONSTRAINT github_membership_snapshots_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_authority_id_key UNIQUE (authority_id);

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_primary_key PRIMARY KEY (attempt_id, fencing_token);

ALTER TABLE ONLY github_oidc_issuance_slots
    ADD CONSTRAINT github_oidc_issuance_slots_primary_key PRIMARY KEY (authority_id, audience_key_sha256);

ALTER TABLE ONLY github_oidc_issuance_slots
    ADD CONSTRAINT github_oidc_issuance_slots_token_id_key UNIQUE (token_id);

ALTER TABLE ONLY github_oidc_key_deadlines
    ADD CONSTRAINT github_oidc_key_deadlines_primary_key PRIMARY KEY (key_use, key_id);

ALTER TABLE ONLY github_organization_membership_observations
    ADD CONSTRAINT github_organization_membership_observations_primary_key PRIMARY KEY (tenant_id, snapshot_id, organization_id);

ALTER TABLE ONLY github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_pkey PRIMARY KEY (provider_delivery_id);

ALTER TABLE ONLY github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_tenant_check_unique UNIQUE (tenant_id, github_check_subject_id);

ALTER TABLE ONLY github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_tenant_repository_delivery_un UNIQUE (tenant_id, repository_id, provider_delivery_id);

ALTER TABLE ONLY github_provider_manifest_current
    ADD CONSTRAINT github_provider_manifest_current_pkey PRIMARY KEY (provider_connection_id);

ALTER TABLE ONLY github_provider_manifest_current
    ADD CONSTRAINT github_provider_manifest_current_repository_unique UNIQUE (tenant_id, repository_id);

ALTER TABLE github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_digest_canonical CHECK ((manifest_digest = automata_github_provider_manifest_digest(github_provider_manifest_revisions.*)));

ALTER TABLE ONLY github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_exact_key_unique UNIQUE (tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest);

ALTER TABLE ONLY github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_owner_exact_unique UNIQUE (tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest, github_repository_owner_id);

ALTER TABLE ONLY github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_primary_key PRIMARY KEY (provider_connection_id, manifest_revision);

ALTER TABLE ONLY github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_tenant_key_unique UNIQUE (tenant_id, provider_connection_id, manifest_revision);

ALTER TABLE ONLY github_repository_dispatch_pending_evidence
    ADD CONSTRAINT github_repository_dispatch_pending_evidence_pkey PRIMARY KEY (provider_delivery_id);

ALTER TABLE ONLY github_repository_dispatch_pending_evidence
    ADD CONSTRAINT github_repository_dispatch_pending_tenant_delivery_unique UNIQUE (tenant_id, provider_delivery_id);

ALTER TABLE ONLY github_role_mappings
    ADD CONSTRAINT github_role_mappings_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY github_runtime_authority_lease_renewal_receipts
    ADD CONSTRAINT github_runtime_authority_lease_renewal_predecessor_unique UNIQUE (attempt_id, fencing_token, previous_lease_expires_at_ms);

ALTER TABLE ONLY github_runtime_authority_lease_renewal_receipts
    ADD CONSTRAINT github_runtime_authority_lease_renewal_receipts_pk PRIMARY KEY (attempt_id, fencing_token, renewed_lease_expires_at_ms);

ALTER TABLE ONLY github_runtime_authority_mint_begins
    ADD CONSTRAINT github_runtime_authority_mint_begins_pk PRIMARY KEY (attempt_id, fencing_token, claim_fence);

ALTER TABLE ONLY github_runtime_authority_mint_claims
    ADD CONSTRAINT github_runtime_authority_mint_claims_pk PRIMARY KEY (attempt_id, fencing_token, claim_fence);

ALTER TABLE ONLY github_runtime_authority_operation_receipts
    ADD CONSTRAINT github_runtime_authority_operation_receipts_pk PRIMARY KEY (attempt_id, fencing_token, operation_kind, claim_fence);

ALTER TABLE ONLY github_runtime_authority_operation_transitions
    ADD CONSTRAINT github_runtime_authority_operation_transitions_pk PRIMARY KEY (attempt_id, fencing_token, operation_kind, claim_fence);

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_primary_key PRIMARY KEY (attempt_id, fencing_token);

ALTER TABLE ONLY github_runtime_authority_revocation_claims
    ADD CONSTRAINT github_runtime_authority_revocation_claims_pk PRIMARY KEY (attempt_id, fencing_token, claim_fence);

ALTER TABLE ONLY github_schedule_discovery_claims
    ADD CONSTRAINT github_schedule_discovery_claims_pkey PRIMARY KEY (discovery_id);

ALTER TABLE ONLY github_schedule_fire_attempts
    ADD CONSTRAINT github_schedule_fire_attempts_fence_unique UNIQUE (fire_id, claim_fence);

ALTER TABLE ONLY github_schedule_fire_attempts
    ADD CONSTRAINT github_schedule_fire_attempts_primary_key PRIMARY KEY (fire_id, attempt);

ALTER TABLE ONLY github_schedule_fires
    ADD CONSTRAINT github_schedule_fires_entry_time_unique UNIQUE (registry_id, entry_ordinal, scheduled_at_ms);

ALTER TABLE ONLY github_schedule_fires
    ADD CONSTRAINT github_schedule_fires_exact_identity_unique UNIQUE (tenant_id, repository_id, provider_connection_id, fire_id, registry_id, entry_ordinal, scheduled_at_ms);

ALTER TABLE ONLY github_schedule_fires
    ADD CONSTRAINT github_schedule_fires_pkey PRIMARY KEY (fire_id);

ALTER TABLE ONLY github_schedule_fires
    ADD CONSTRAINT github_schedule_fires_run_identity_unique UNIQUE (tenant_id, repository_id, fire_id);

ALTER TABLE ONLY github_schedule_fires
    ADD CONSTRAINT github_schedule_fires_subject_identity_unique UNIQUE (tenant_id, repository_id, provider_connection_id, fire_id);

ALTER TABLE ONLY github_schedule_registry_current
    ADD CONSTRAINT github_schedule_registry_current_primary_key PRIMARY KEY (tenant_id, repository_id, provider_connection_id);

ALTER TABLE ONLY github_schedule_registry_current
    ADD CONSTRAINT github_schedule_registry_current_registry_unique UNIQUE (tenant_id, repository_id, provider_connection_id, registry_id);

ALTER TABLE ONLY github_schedule_registry_entries
    ADD CONSTRAINT github_schedule_registry_entries_digest_unique UNIQUE (registry_id, entry_digest);

ALTER TABLE ONLY github_schedule_registry_entries
    ADD CONSTRAINT github_schedule_registry_entries_primary_key PRIMARY KEY (registry_id, ordinal);

ALTER TABLE ONLY github_schedule_registry_entries
    ADD CONSTRAINT github_schedule_registry_entries_source_identity_unique UNIQUE (registry_id, workflow_path, schedule_ordinal);

ALTER TABLE ONLY github_schedule_registry_revisions
    ADD CONSTRAINT github_schedule_registry_revisions_discovery_unique UNIQUE (discovery_id);

ALTER TABLE ONLY github_schedule_registry_revisions
    ADD CONSTRAINT github_schedule_registry_revisions_exact_unique UNIQUE (tenant_id, repository_id, provider_connection_id, registry_id, manifest_revision, manifest_digest, default_branch_ref, source_revision, github_repository_owner_id);

ALTER TABLE ONLY github_schedule_registry_revisions
    ADD CONSTRAINT github_schedule_registry_revisions_identity_unique UNIQUE (tenant_id, repository_id, provider_connection_id, registry_id);

ALTER TABLE ONLY github_schedule_registry_revisions
    ADD CONSTRAINT github_schedule_registry_revisions_pkey PRIMARY KEY (registry_id);

ALTER TABLE ONLY github_schedule_registry_revisions
    ADD CONSTRAINT github_schedule_registry_revisions_replay_unique UNIQUE (tenant_id, repository_id, provider_connection_id, manifest_revision, source_revision, inventory_digest);

ALTER TABLE ONLY github_schedule_registry_seals
    ADD CONSTRAINT github_schedule_registry_seals_pkey PRIMARY KEY (registry_id);

ALTER TABLE ONLY github_schedule_runtime
    ADD CONSTRAINT github_schedule_runtime_primary_key PRIMARY KEY (tenant_id, repository_id, provider_connection_id, entry_ordinal);

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_pkey PRIMARY KEY (schedule_fire_id);

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_run_unique UNIQUE (repository_id, run_id);

ALTER TABLE ONLY github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_exact_config_unique UNIQUE (tenant_id, repository_id, provider_connection_id, provider_installation_id, service_scope, app_configuration_revision, policy_revision, configuration_fingerprint);

ALTER TABLE github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_identity_digest_canonical CHECK ((identity_digest = automata_github_server_service_identity_digest(github_server_service_authorities.*)));

ALTER TABLE ONLY github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_pkey PRIMARY KEY (id);

ALTER TABLE ONLY github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_repository_scope_revision_uni UNIQUE (tenant_id, repository_id, service_scope, app_configuration_revision, policy_revision);

ALTER TABLE ONLY github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_tenant_id_unique UNIQUE (tenant_id, id);

ALTER TABLE ONLY github_server_service_authority_handoffs
    ADD CONSTRAINT github_server_service_authority_handoffs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY github_server_service_authority_issuances
    ADD CONSTRAINT github_server_service_authority_issuances_pkey PRIMARY KEY (authority_id, generation);

ALTER TABLE ONLY github_server_service_authority_handoffs
    ADD CONSTRAINT github_server_service_handoffs_exact_consumer_unique UNIQUE (authority_id, consumer_id, consumer_owner_id, consumer_claim_fence, consumer_action, consumer_revision);

ALTER TABLE ONLY github_server_service_authority_issuances
    ADD CONSTRAINT github_server_service_issuances_tenant_key_unique UNIQUE (tenant_id, authority_id, generation);

ALTER TABLE ONLY github_team_membership_observations
    ADD CONSTRAINT github_team_membership_observations_primary_key PRIMARY KEY (tenant_id, snapshot_id, team_id);

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_primary_key PRIMARY KEY (tenant_id, operation_id);

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_run_unique UNIQUE (repository_id, run_id);

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_subject_unique UNIQUE (github_check_subject_id);

ALTER TABLE ONLY github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_delivery_path_run_unique UNIQUE (provider_delivery_id, workflow_path, run_id);

ALTER TABLE ONLY github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_exact_digest_unique UNIQUE (repository_id, run_id, subject_evidence_sha256);

ALTER TABLE ONLY github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_primary_key PRIMARY KEY (repository_id, run_id);

ALTER TABLE ONLY delegated_actor_identities
    ADD CONSTRAINT delegated_actor_identities_pkey PRIMARY KEY (issuer, subject);

ALTER TABLE ONLY delegated_actor_identities
    ADD CONSTRAINT delegated_actor_identities_principal_key UNIQUE (principal_id);

ALTER TABLE ONLY delegated_actor_identities
    ADD CONSTRAINT delegated_actor_identities_mapping_key UNIQUE (issuer, subject, principal_id);

ALTER TABLE ONLY human_auth_installation_state
    ADD CONSTRAINT human_auth_installation_state_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY human_login_transactions
    ADD CONSTRAINT human_login_transactions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY human_principals
    ADD CONSTRAINT human_principals_pkey PRIMARY KEY (id);

ALTER TABLE ONLY human_provider_identities
    ADD CONSTRAINT human_provider_identities_primary_key PRIMARY KEY (provider_id, provider_subject);

ALTER TABLE ONLY human_provider_identities
    ADD CONSTRAINT human_provider_identities_principal_identity_unique UNIQUE (principal_id, provider_id, provider_subject);

ALTER TABLE ONLY human_provider_identities
    ADD CONSTRAINT human_provider_identities_principal_provider_unique UNIQUE (principal_id, provider_id);

ALTER TABLE ONLY human_provider_tokens
    ADD CONSTRAINT human_provider_tokens_primary_key PRIMARY KEY (envelope_record_id);

ALTER TABLE ONLY human_sessions
    ADD CONSTRAINT human_sessions_actor_unique UNIQUE (tenant_id, principal_id, id);

ALTER TABLE ONLY human_sessions
    ADD CONSTRAINT human_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY human_sessions
    ADD CONSTRAINT human_sessions_tenant_id_unique UNIQUE (tenant_id, id);

ALTER TABLE ONLY human_sessions
    ADD CONSTRAINT human_sessions_token_hash_unique UNIQUE (token_hash_key_id, token_hash);

ALTER TABLE ONLY job_attempts
    ADD CONSTRAINT job_attempts_job_number_unique UNIQUE (job_id, attempt_number);

ALTER TABLE ONLY job_attempts
    ADD CONSTRAINT job_attempts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY job_dependencies
    ADD CONSTRAINT job_dependencies_primary_key PRIMARY KEY (run_id, job_id, prerequisite_job_id);

ALTER TABLE ONLY job_environment_gates
    ADD CONSTRAINT job_environment_gates_exact_job UNIQUE (tenant_id, repository_id, run_id, job_id, attempt_id);

ALTER TABLE ONLY job_environment_gates
    ADD CONSTRAINT job_environment_gates_primary_key PRIMARY KEY (attempt_id);

ALTER TABLE ONLY job_missing_secret_bindings
    ADD CONSTRAINT job_missing_secret_bindings_primary_key PRIMARY KEY (attempt_id, canonical_name);

ALTER TABLE ONLY job_missing_variable_bindings
    ADD CONSTRAINT job_missing_variable_bindings_primary_key PRIMARY KEY (attempt_id, canonical_name);

ALTER TABLE ONLY job_secret_bindings
    ADD CONSTRAINT job_secret_bindings_grant_unique UNIQUE (tenant_id, grant_id);

ALTER TABLE ONLY job_secret_bindings
    ADD CONSTRAINT job_secret_bindings_primary_key PRIMARY KEY (attempt_id, canonical_name);

ALTER TABLE ONLY job_secret_selections
    ADD CONSTRAINT job_secret_selections_primary_key PRIMARY KEY (attempt_id, canonical_name);

ALTER TABLE ONLY job_variable_bindings
    ADD CONSTRAINT job_variable_bindings_primary_key PRIMARY KEY (attempt_id, canonical_name);

ALTER TABLE ONLY jobs
    ADD CONSTRAINT jobs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY jobs
    ADD CONSTRAINT jobs_run_id_artifact_unique UNIQUE (run_id, id);

ALTER TABLE ONLY jobs
    ADD CONSTRAINT jobs_run_key_unique UNIQUE (run_id, job_key);

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_credential_unique UNIQUE (credential_key_id, credential_sha256);

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_exact_workload UNIQUE (tenant_id, attempt_id, lease_id, fencing_token, runner_session_id, runner_session_epoch, runner_generation, runner_slot, runtime_context_digest, binding_set_digest);

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_operation_unique UNIQUE (operation_id);

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_primary_key PRIMARY KEY (tenant_id, operation_id);

ALTER TABLE ONLY protected_environment_approval_decisions
    ADD CONSTRAINT protected_environment_approval_decisions_primary_key PRIMARY KEY (tenant_id, request_id, principal_id);

ALTER TABLE ONLY protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_one_per_attempt UNIQUE (tenant_id, attempt_id);

ALTER TABLE ONLY protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_requests_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_requests_workload_unique UNIQUE (tenant_id, repository_id, environment_id, run_id, job_id, attempt_id, id);

ALTER TABLE ONLY provider_delivery_inbox
    ADD CONSTRAINT provider_delivery_inbox_pkey PRIMARY KEY (id);

ALTER TABLE ONLY provider_delivery_inbox
    ADD CONSTRAINT provider_delivery_inbox_replay_unique UNIQUE (provider, connection_id, delivery_id);

ALTER TABLE ONLY provider_delivery_inbox
    ADD CONSTRAINT provider_delivery_inbox_tenant_id_unique UNIQUE (id, tenant_id);

ALTER TABLE ONLY provider_delivery_workflow_inventories
    ADD CONSTRAINT provider_delivery_workflow_inventories_digest_unique UNIQUE (tenant_id, inbox_id, inventory_digest);

ALTER TABLE ONLY provider_delivery_workflow_inventories
    ADD CONSTRAINT provider_delivery_workflow_inventories_pkey PRIMARY KEY (inbox_id);

ALTER TABLE ONLY provider_delivery_workflow_inventories
    ADD CONSTRAINT provider_delivery_workflow_inventories_tenant_unique UNIQUE (tenant_id, inbox_id);

ALTER TABLE ONLY provider_delivery_workflow_inventory_entries
    ADD CONSTRAINT provider_delivery_workflow_inventory_entries_ordinal_unique UNIQUE (inbox_id, ordinal);

ALTER TABLE ONLY provider_delivery_workflow_inventory_entries
    ADD CONSTRAINT provider_delivery_workflow_inventory_entries_primary_key PRIMARY KEY (inbox_id, workflow_path);

ALTER TABLE ONLY provider_delivery_workflow_outcomes
    ADD CONSTRAINT provider_delivery_workflow_outcomes_ordinal_unique UNIQUE (inbox_id, ordinal);

ALTER TABLE ONLY provider_delivery_workflow_outcomes
    ADD CONSTRAINT provider_delivery_workflow_outcomes_primary_key PRIMARY KEY (inbox_id, workflow_path);

ALTER TABLE ONLY provider_delivery_workflow_progress
    ADD CONSTRAINT provider_delivery_workflow_progress_primary_key PRIMARY KEY (inbox_id, workflow_path);

ALTER TABLE ONLY rbac_permissions
    ADD CONSTRAINT rbac_permissions_pkey PRIMARY KEY (name);

ALTER TABLE ONLY rbac_role_bindings
    ADD CONSTRAINT rbac_role_bindings_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY rbac_role_permissions
    ADD CONSTRAINT rbac_role_permissions_primary_key PRIMARY KEY (tenant_id, role_id, permission_name);

ALTER TABLE ONLY rbac_roles
    ADD CONSTRAINT rbac_roles_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY rbac_roles
    ADD CONSTRAINT rbac_roles_tenant_name_unique UNIQUE (tenant_id, name);

ALTER TABLE ONLY repositories
    ADD CONSTRAINT repositories_pkey PRIMARY KEY (id);

ALTER TABLE ONLY repositories
    ADD CONSTRAINT repositories_provider_identity_unique UNIQUE (tenant_id, scm_provider, provider_repository_id);

ALTER TABLE ONLY repositories
    ADD CONSTRAINT repositories_tenant_id_unique UNIQUE (tenant_id, id);

ALTER TABLE ONLY repository_environment_reviewers
    ADD CONSTRAINT repository_environment_reviewers_primary_key PRIMARY KEY (tenant_id, repository_id, environment_id, environment_revision, principal_id);

ALTER TABLE ONLY repository_environments
    ADD CONSTRAINT repository_environments_name_unique UNIQUE (tenant_id, repository_id, normalized_name);

ALTER TABLE ONLY repository_environments
    ADD CONSTRAINT repository_environments_primary_key PRIMARY KEY (tenant_id, repository_id, id);

ALTER TABLE ONLY repository_environments
    ADD CONSTRAINT repository_environments_tenant_id_unique UNIQUE (tenant_id, id);

ALTER TABLE ONLY repository_publication_policies
    ADD CONSTRAINT repository_publication_policies_primary_key PRIMARY KEY (tenant_id, repository_id);

ALTER TABLE ONLY repository_publication_policies
    ADD CONSTRAINT repository_publication_policies_repository_unique UNIQUE (repository_id);

ALTER TABLE ONLY runner_command_outbox
    ADD CONSTRAINT runner_command_outbox_operation_unique UNIQUE (runner_session_id, operation_id);

ALTER TABLE ONLY runner_command_outbox
    ADD CONSTRAINT runner_command_outbox_primary_key PRIMARY KEY (runner_session_id, command_sequence);

ALTER TABLE ONLY runner_groups
    ADD CONSTRAINT runner_groups_normalized_unique UNIQUE (tenant_id, normalized_name);

ALTER TABLE ONLY runner_groups
    ADD CONSTRAINT runner_groups_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runner_groups
    ADD CONSTRAINT runner_groups_tenant_id_unique UNIQUE (tenant_id, id);

ALTER TABLE ONLY runner_lease_offer_publications
    ADD CONSTRAINT runner_lease_offer_publications_command_unique UNIQUE (runner_session_id, command_sequence);

ALTER TABLE ONLY runner_lease_offer_publications
    ADD CONSTRAINT runner_lease_offer_publications_primary_key PRIMARY KEY (runner_session_id, request_operation_id);

ALTER TABLE ONLY runner_lease_offer_publications
    ADD CONSTRAINT runner_lease_offer_publications_receipt_binding_unique UNIQUE (runner_session_id, request_operation_id, command_sequence);

ALTER TABLE ONLY runner_lease_request_heads
    ADD CONSTRAINT runner_lease_request_heads_operation_unique UNIQUE (runner_session_id, operation_id);

ALTER TABLE ONLY runner_lease_request_heads
    ADD CONSTRAINT runner_lease_request_heads_primary_key PRIMARY KEY (runner_session_id, runner_slot);

ALTER TABLE ONLY runner_machine_certificates
    ADD CONSTRAINT runner_machine_certificates_pkey PRIMARY KEY (leaf_sha256);

ALTER TABLE ONLY runner_enrollment_tokens
    ADD CONSTRAINT runner_enrollment_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runner_enrollment_tokens
    ADD CONSTRAINT runner_enrollment_tokens_digest_unique UNIQUE (token_sha256);

ALTER TABLE ONLY runner_operation_receipts
    ADD CONSTRAINT runner_operation_receipts_primary_key PRIMARY KEY (runner_session_id, operation_id);

ALTER TABLE ONLY runner_queue_cursors
    ADD CONSTRAINT runner_queue_cursors_primary_key PRIMARY KEY (runner_id, runner_slot);

ALTER TABLE ONLY runner_rpc_receipts
    ADD CONSTRAINT runner_rpc_receipts_primary_key PRIMARY KEY (runner_session_id, operation_id);

ALTER TABLE ONLY runner_sessions
    ADD CONSTRAINT runner_sessions_fence_unique UNIQUE (runner_id, id, session_epoch, runner_generation);

ALTER TABLE ONLY runner_sessions
    ADD CONSTRAINT runner_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runner_sessions
    ADD CONSTRAINT runner_sessions_runner_epoch_unique UNIQUE (runner_id, session_epoch);

ALTER TABLE ONLY runners
    ADD CONSTRAINT runners_external_identity_unique UNIQUE (external_identity);

ALTER TABLE ONLY runners
    ADD CONSTRAINT runners_name_unique UNIQUE (tenant_id, normalized_name);

ALTER TABLE ONLY runners
    ADD CONSTRAINT runners_pkey PRIMARY KEY (id);

ALTER TABLE ONLY runners
    ADD CONSTRAINT runners_tenant_id_id_unique UNIQUE (tenant_id, id);

ALTER TABLE ONLY secret_cleanup_outbox
    ADD CONSTRAINT secret_cleanup_outbox_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY secret_cleanup_outbox
    ADD CONSTRAINT secret_cleanup_outbox_pkey PRIMARY KEY (sequence);

ALTER TABLE ONLY secret_custody_key_canaries
    ADD CONSTRAINT secret_custody_key_canaries_pkey PRIMARY KEY (wrapping_key_id);

ALTER TABLE ONLY secret_key_rotation_items
    ADD CONSTRAINT secret_key_rotation_items_primary_key PRIMARY KEY (tenant_id, rotation_id, secret_version_id);

ALTER TABLE ONLY secret_key_rotations
    ADD CONSTRAINT secret_key_rotations_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY secret_mutation_recovery_outbox
    ADD CONSTRAINT secret_mutation_recovery_outbox_mutation_unique UNIQUE (tenant_id, mutation_id);

ALTER TABLE ONLY secret_mutation_recovery_outbox
    ADD CONSTRAINT secret_mutation_recovery_outbox_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY secret_mutation_recovery_outbox
    ADD CONSTRAINT secret_mutation_recovery_outbox_pkey PRIMARY KEY (sequence);

ALTER TABLE ONLY secret_policies
    ADD CONSTRAINT secret_policies_primary_key PRIMARY KEY (tenant_id, secret_id);

ALTER TABLE ONLY secret_provider_configuration_envelope_heads
    ADD CONSTRAINT secret_provider_configuration_envelope_heads_primary_key PRIMARY KEY (tenant_id, provider_id);

ALTER TABLE ONLY secret_provider_configuration_envelopes
    ADD CONSTRAINT secret_provider_configuration_envelopes_primary_key PRIMARY KEY (tenant_id, provider_id, envelope_generation);

ALTER TABLE ONLY secret_provider_lease_envelope_heads
    ADD CONSTRAINT secret_provider_lease_envelope_heads_primary_key PRIMARY KEY (tenant_id, provider_lease_record_id);

ALTER TABLE ONLY secret_provider_lease_envelopes
    ADD CONSTRAINT secret_provider_lease_envelopes_primary_key PRIMARY KEY (tenant_id, provider_lease_record_id, envelope_generation);

ALTER TABLE ONLY secret_provider_leases
    ADD CONSTRAINT secret_provider_leases_grant_unique UNIQUE (tenant_id, provider_id, workload_grant_id);

ALTER TABLE ONLY secret_provider_leases
    ADD CONSTRAINT secret_provider_leases_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY secret_provider_leases
    ADD CONSTRAINT secret_provider_leases_provider_unique UNIQUE (tenant_id, id, provider_id);

ALTER TABLE ONLY secret_provider_locator_envelope_heads
    ADD CONSTRAINT secret_provider_locator_envelope_heads_primary_key PRIMARY KEY (tenant_id, secret_id);

ALTER TABLE ONLY secret_provider_locator_envelopes
    ADD CONSTRAINT secret_provider_locator_envelopes_primary_key PRIMARY KEY (tenant_id, secret_id, envelope_generation);

ALTER TABLE ONLY secret_provider_version_envelope_heads
    ADD CONSTRAINT secret_provider_version_envelope_heads_primary_key PRIMARY KEY (tenant_id, secret_version_id);

ALTER TABLE ONLY secret_provider_version_envelopes
    ADD CONSTRAINT secret_provider_version_envelopes_primary_key PRIMARY KEY (tenant_id, secret_version_id, envelope_generation);

ALTER TABLE ONLY secret_providers
    ADD CONSTRAINT secret_providers_primary_key PRIMARY KEY (tenant_id, provider_id);

ALTER TABLE ONLY secret_repository_access
    ADD CONSTRAINT secret_repository_access_primary_key PRIMARY KEY (tenant_id, secret_id, repository_id);

ALTER TABLE ONLY secret_version_envelope_heads
    ADD CONSTRAINT secret_version_envelope_heads_primary_key PRIMARY KEY (tenant_id, secret_version_id);

ALTER TABLE ONLY secret_version_envelopes
    ADD CONSTRAINT secret_version_envelopes_primary_key PRIMARY KEY (tenant_id, secret_version_id, envelope_generation);

ALTER TABLE ONLY secret_version_lifecycle
    ADD CONSTRAINT secret_version_lifecycle_mutation_unique UNIQUE (tenant_id, mutation_id);

ALTER TABLE ONLY secret_version_lifecycle
    ADD CONSTRAINT secret_version_lifecycle_primary_key PRIMARY KEY (tenant_id, secret_version_id);

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_lifecycle_identity UNIQUE (tenant_id, mutation_id, secret_id, provider_id);

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_primary_key PRIMARY KEY (tenant_id, mutation_id);

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_provider_request_unique UNIQUE (tenant_id, provider_id, provider_create_request_id);

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_reserved_version_unique UNIQUE (tenant_id, secret_id, reserved_version_number);

ALTER TABLE ONLY secret_versions
    ADD CONSTRAINT secret_versions_create_request_unique UNIQUE (tenant_id, provider_id, create_request_id);

ALTER TABLE ONLY secret_versions
    ADD CONSTRAINT secret_versions_identity_unique UNIQUE (tenant_id, id, secret_id, version_number);

ALTER TABLE ONLY secret_versions
    ADD CONSTRAINT secret_versions_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY secret_versions
    ADD CONSTRAINT secret_versions_provider_unique UNIQUE (tenant_id, id, secret_id, version_number, provider_id);

ALTER TABLE ONLY secret_versions
    ADD CONSTRAINT secret_versions_secret_number_unique UNIQUE (tenant_id, secret_id, version_number);

ALTER TABLE ONLY secret_versions
    ADD CONSTRAINT secret_versions_storage_unique UNIQUE (tenant_id, id, secret_id, version_number, storage_kind);

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_attempt_secret_unique UNIQUE (tenant_id, attempt_id, secret_id, secret_version_id, grant_mode);

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_authority_unique UNIQUE (authority_digest_key_id, authority_digest);

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_provider_unique UNIQUE (tenant_id, id, provider_id);

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_scope_kind_unique UNIQUE (tenant_id, id, scope_kind);

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_scope_unique UNIQUE (tenant_id, id, scope_kind, repository_id, environment_id);

ALTER TABLE ONLY security_audit_events
    ADD CONSTRAINT security_audit_events_event_id_key UNIQUE (event_id);

ALTER TABLE ONLY security_audit_events
    ADD CONSTRAINT security_audit_events_pkey PRIMARY KEY (sequence);

ALTER TABLE ONLY tenant_human_memberships
    ADD CONSTRAINT tenant_human_memberships_primary_key PRIMARY KEY (tenant_id, principal_id);

ALTER TABLE ONLY tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workspace_provisioning_operations
    ADD CONSTRAINT workspace_provisioning_operations_pkey PRIMARY KEY (authority_id, operation_id);

ALTER TABLE ONLY workflow_admission_receipts
    ADD CONSTRAINT workflow_admission_receipts_primary_key PRIMARY KEY (tenant_id, idempotency_kind, idempotency_key);

ALTER TABLE ONLY workflow_artifact_block_commits
    ADD CONSTRAINT workflow_artifact_block_commits_pkey PRIMARY KEY (artifact_id);

ALTER TABLE ONLY workflow_artifact_blocks
    ADD CONSTRAINT workflow_artifact_blocks_primary_key PRIMARY KEY (artifact_id, block_id);

ALTER TABLE ONLY workflow_artifacts
    ADD CONSTRAINT workflow_artifacts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workflow_artifacts
    ADD CONSTRAINT workflow_artifacts_run_name_unique UNIQUE (run_id, name);

ALTER TABLE ONLY workflow_artifacts
    ADD CONSTRAINT workflow_artifacts_upload_id_key UNIQUE (upload_id);

ALTER TABLE ONLY workflow_definitions
    ADD CONSTRAINT workflow_definitions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workflow_definitions
    ADD CONSTRAINT workflow_definitions_repository_id_unique UNIQUE (repository_id, id);

ALTER TABLE ONLY workflow_definitions
    ADD CONSTRAINT workflow_definitions_repository_path_unique UNIQUE (repository_id, path);

ALTER TABLE ONLY logical_workflow_activation_preparation_prerequisites
    ADD CONSTRAINT logical_workflow_activation_pre_logical_job_id_source_order_key UNIQUE (logical_job_id, source_order);

ALTER TABLE ONLY logical_workflow_activation_preparation_prerequisites
    ADD CONSTRAINT logical_workflow_activation_prep_logical_job_id_logical_key_key UNIQUE (logical_job_id, logical_key);

ALTER TABLE ONLY logical_workflow_activation_preparation_claims
    ADD CONSTRAINT logical_workflow_activation_preparation_claims_identity_unique UNIQUE (run_id, invocation_id, logical_job_id);

ALTER TABLE ONLY logical_workflow_activation_preparation_claims
    ADD CONSTRAINT logical_workflow_activation_preparation_claims_pkey PRIMARY KEY (logical_job_id);

ALTER TABLE ONLY logical_workflow_activation_preparation_outputs
    ADD CONSTRAINT logical_workflow_activation_preparation_outputs_pkey PRIMARY KEY (logical_job_id, prerequisite_job_id, output_name);

ALTER TABLE ONLY logical_workflow_activation_preparation_prerequisites
    ADD CONSTRAINT logical_workflow_activation_preparation_prerequisites_pkey PRIMARY KEY (logical_job_id, prerequisite_job_id);

ALTER TABLE ONLY logical_workflow_activation_preparations
    ADD CONSTRAINT logical_workflow_activation_preparations_pkey PRIMARY KEY (logical_job_id);

ALTER TABLE ONLY logical_workflow_activation_publications
    ADD CONSTRAINT logical_workflow_activation_publications_primary_key PRIMARY KEY (run_id, invocation_id, logical_job_id);

ALTER TABLE ONLY logical_workflow_activation_work_quarantines
    ADD CONSTRAINT logical_workflow_activation_quarantine_selection_unique UNIQUE (selection_id);

ALTER TABLE ONLY logical_workflow_activation_renewal_receipts
    ADD CONSTRAINT logical_workflow_activation_renewal_receipts_pk PRIMARY KEY (logical_job_id, authority_kind, predecessor_generation);

ALTER TABLE ONLY logical_workflow_activation_renewal_receipts
    ADD CONSTRAINT logical_workflow_activation_renewal_selection_unique UNIQUE (selection_id, authority_kind, logical_job_id, predecessor_generation);

ALTER TABLE ONLY logical_workflow_activation_work_quarantines
    ADD CONSTRAINT logical_workflow_activation_work_quarantines_pkey PRIMARY KEY (logical_job_id);

ALTER TABLE ONLY logical_workflow_activation_work_selections
    ADD CONSTRAINT logical_workflow_activation_work_selections_pkey PRIMARY KEY (selection_id);

ALTER TABLE ONLY logical_workflow_concrete_jobs
    ADD CONSTRAINT logical_workflow_concrete_jobs_initial_attempt_id_key UNIQUE (initial_attempt_id);

ALTER TABLE ONLY logical_workflow_concrete_jobs
    ADD CONSTRAINT logical_workflow_concrete_jobs_job_id_key UNIQUE (job_id);

ALTER TABLE ONLY logical_workflow_concrete_jobs
    ADD CONSTRAINT logical_workflow_concrete_jobs_pkey PRIMARY KEY (instance_id);

ALTER TABLE ONLY logical_workflow_concurrency_cancellations
    ADD CONSTRAINT logical_workflow_concurrency_cancellations_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY logical_workflow_dependencies
    ADD CONSTRAINT logical_workflow_dependencies_primary_key PRIMARY KEY (run_id, invocation_id, logical_job_id, prerequisite_job_id);

ALTER TABLE ONLY logical_workflow_instance_result_claims
    ADD CONSTRAINT logical_workflow_instance_result_claims_instance_id_key UNIQUE (instance_id);

ALTER TABLE ONLY logical_workflow_instance_result_claims
    ADD CONSTRAINT logical_workflow_instance_result_claims_job_id_key UNIQUE (job_id);

ALTER TABLE ONLY logical_workflow_instance_result_claims
    ADD CONSTRAINT logical_workflow_instance_result_claims_pkey PRIMARY KEY (attempt_id);

ALTER TABLE ONLY logical_workflow_instance_result_due
    ADD CONSTRAINT logical_workflow_instance_result_due_pkey PRIMARY KEY (attempt_id);

ALTER TABLE ONLY logical_workflow_instance_result_outputs
    ADD CONSTRAINT logical_workflow_instance_result_outputs_pkey PRIMARY KEY (instance_id, output_name);

ALTER TABLE ONLY logical_workflow_instance_result_quarantines
    ADD CONSTRAINT logical_workflow_instance_result_quarantines_pkey PRIMARY KEY (attempt_id);

ALTER TABLE ONLY logical_workflow_instance_result_selections
    ADD CONSTRAINT logical_workflow_instance_result_selections_generation_unique UNIQUE (attempt_id, generation);

ALTER TABLE ONLY logical_workflow_instance_result_selections
    ADD CONSTRAINT logical_workflow_instance_result_selections_pkey PRIMARY KEY (selection_id);

ALTER TABLE ONLY logical_workflow_instance_results
    ADD CONSTRAINT logical_workflow_instance_results_attempt_id_key UNIQUE (attempt_id);

ALTER TABLE ONLY logical_workflow_instance_results
    ADD CONSTRAINT logical_workflow_instance_results_job_id_key UNIQUE (job_id);

ALTER TABLE ONLY logical_workflow_instance_results
    ADD CONSTRAINT logical_workflow_instance_results_pkey PRIMARY KEY (instance_id);

ALTER TABLE ONLY logical_workflow_instance_results
    ADD CONSTRAINT logical_workflow_instance_results_terminal_order_unique UNIQUE (logical_job_id, terminal_ordinal);

ALTER TABLE ONLY logical_workflow_instances
    ADD CONSTRAINT logical_workflow_instances_full_identity_unique UNIQUE (run_id, invocation_id, logical_job_id, id);

ALTER TABLE ONLY logical_workflow_instances
    ADD CONSTRAINT logical_workflow_instances_job_index_unique UNIQUE (run_id, invocation_id, logical_job_id, matrix_index);

ALTER TABLE ONLY logical_workflow_instances
    ADD CONSTRAINT logical_workflow_instances_pkey PRIMARY KEY (id);

ALTER TABLE ONLY logical_workflow_invocations
    ADD CONSTRAINT logical_workflow_invocations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY logical_workflow_invocations
    ADD CONSTRAINT logical_workflow_invocations_run_id_unique UNIQUE (run_id, id);

ALTER TABLE ONLY logical_workflow_job_environment_evidence
    ADD CONSTRAINT logical_workflow_job_environment_evidence_pkey PRIMARY KEY (instance_id);

ALTER TABLE ONLY logical_workflow_job_result_claims
    ADD CONSTRAINT logical_workflow_job_result_claims_full_identity_unique UNIQUE (run_id, invocation_id, logical_job_id);

ALTER TABLE ONLY logical_workflow_job_result_claims
    ADD CONSTRAINT logical_workflow_job_result_claims_pkey PRIMARY KEY (logical_job_id);

ALTER TABLE ONLY logical_workflow_job_result_due
    ADD CONSTRAINT logical_workflow_job_result_due_pkey PRIMARY KEY (logical_job_id);

ALTER TABLE ONLY logical_workflow_job_result_instances
    ADD CONSTRAINT logical_workflow_job_result_i_logical_job_id_terminal_ordin_key UNIQUE (logical_job_id, terminal_ordinal);

ALTER TABLE ONLY logical_workflow_job_result_instances
    ADD CONSTRAINT logical_workflow_job_result_inst_logical_job_id_instance_id_key UNIQUE (logical_job_id, instance_id);

ALTER TABLE ONLY logical_workflow_job_result_instances
    ADD CONSTRAINT logical_workflow_job_result_instances_pkey PRIMARY KEY (logical_job_id, matrix_index);

ALTER TABLE ONLY logical_workflow_job_result_outputs
    ADD CONSTRAINT logical_workflow_job_result_outputs_pkey PRIMARY KEY (logical_job_id, output_name);

ALTER TABLE ONLY logical_workflow_job_result_prerequisites
    ADD CONSTRAINT logical_workflow_job_result_p_logical_job_id_prerequisite_s_key UNIQUE (logical_job_id, prerequisite_source_order);

ALTER TABLE ONLY logical_workflow_job_result_prerequisites
    ADD CONSTRAINT logical_workflow_job_result_prerequisites_pkey PRIMARY KEY (logical_job_id, prerequisite_job_id);

ALTER TABLE ONLY logical_workflow_job_result_quarantines
    ADD CONSTRAINT logical_workflow_job_result_quarantines_pkey PRIMARY KEY (logical_job_id);

ALTER TABLE ONLY logical_workflow_job_result_selections
    ADD CONSTRAINT logical_workflow_job_result_selections_generation_unique UNIQUE (logical_job_id, generation);

ALTER TABLE ONLY logical_workflow_job_result_selections
    ADD CONSTRAINT logical_workflow_job_result_selections_pkey PRIMARY KEY (selection_id);

ALTER TABLE ONLY logical_workflow_job_results
    ADD CONSTRAINT logical_workflow_job_results_pkey PRIMARY KEY (logical_job_id);

ALTER TABLE ONLY logical_workflow_job_terminal_counters
    ADD CONSTRAINT logical_workflow_job_terminal_counters_pkey PRIMARY KEY (logical_job_id);

ALTER TABLE ONLY logical_workflow_jobs
    ADD CONSTRAINT logical_workflow_jobs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY logical_workflow_jobs
    ADD CONSTRAINT logical_workflow_jobs_run_invocation_id_unique UNIQUE (run_id, invocation_id, id);

ALTER TABLE ONLY logical_workflow_jobs
    ADD CONSTRAINT logical_workflow_jobs_run_key_unique UNIQUE (run_id, invocation_id, logical_key);

ALTER TABLE ONLY logical_workflow_jobs
    ADD CONSTRAINT logical_workflow_jobs_run_order_unique UNIQUE (run_id, invocation_id, source_order);

ALTER TABLE ONLY logical_workflow_materialization_claims
    ADD CONSTRAINT logical_workflow_materialization_claims_expected_attempt_id_key UNIQUE (expected_attempt_id);

ALTER TABLE ONLY logical_workflow_materialization_claims
    ADD CONSTRAINT logical_workflow_materialization_claims_expected_job_id_key UNIQUE (expected_job_id);

ALTER TABLE ONLY logical_workflow_materialization_claims
    ADD CONSTRAINT logical_workflow_materialization_claims_full_identity_unique UNIQUE (run_id, invocation_id, logical_job_id, instance_id);

ALTER TABLE ONLY logical_workflow_materialization_claims
    ADD CONSTRAINT logical_workflow_materialization_claims_pkey PRIMARY KEY (instance_id);

ALTER TABLE ONLY logical_workflow_materialization_work_quarantines
    ADD CONSTRAINT logical_workflow_materialization_quarantine_selection_unique UNIQUE (selection_id);

ALTER TABLE ONLY logical_workflow_materialization_renewal_receipts
    ADD CONSTRAINT logical_workflow_materialization_renewal_receipts_pk PRIMARY KEY (instance_id, predecessor_generation);

ALTER TABLE ONLY logical_workflow_materialization_renewal_receipts
    ADD CONSTRAINT logical_workflow_materialization_renewal_selection_unique UNIQUE (selection_id, instance_id, predecessor_generation);

ALTER TABLE ONLY logical_workflow_materialization_work_quarantines
    ADD CONSTRAINT logical_workflow_materialization_work_quarantines_pkey PRIMARY KEY (instance_id);

ALTER TABLE ONLY logical_workflow_materialization_work_selections
    ADD CONSTRAINT logical_workflow_materialization_work_selections_pkey PRIMARY KEY (selection_id);

ALTER TABLE ONLY logical_workflow_result_selection_replay_horizons
    ADD CONSTRAINT logical_workflow_result_selection_replay_horizons_pkey PRIMARY KEY (queue_name);

ALTER TABLE ONLY logical_workflow_reusable_call_output_contracts
    ADD CONSTRAINT logical_workflow_reusable_call_output_contracts_pk PRIMARY KEY (run_id, child_invocation_id);

ALTER TABLE ONLY logical_workflow_reusable_call_output_mappings
    ADD CONSTRAINT logical_workflow_reusable_call_output_mappings_order_unique UNIQUE (run_id, child_invocation_id, source_order);

ALTER TABLE ONLY logical_workflow_reusable_call_output_mappings
    ADD CONSTRAINT logical_workflow_reusable_call_output_mappings_pk PRIMARY KEY (run_id, child_invocation_id, parent_output_name);

ALTER TABLE ONLY logical_workflow_reusable_call_publications
    ADD CONSTRAINT logical_workflow_reusable_call_publications_child_unique UNIQUE (run_id, child_invocation_id);

ALTER TABLE ONLY logical_workflow_reusable_call_publications
    ADD CONSTRAINT logical_workflow_reusable_call_publications_instance_unique UNIQUE (caller_instance_id);

ALTER TABLE ONLY logical_workflow_reusable_call_publications
    ADD CONSTRAINT logical_workflow_reusable_call_publications_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY logical_workflow_reusable_call_publications
    ADD CONSTRAINT logical_workflow_reusable_call_publications_pk PRIMARY KEY (run_id, parent_invocation_id, caller_logical_job_id);

ALTER TABLE ONLY logical_workflow_reusable_call_results
    ADD CONSTRAINT logical_workflow_reusable_call_resu_completion_operation_id_key UNIQUE (completion_operation_id);

ALTER TABLE ONLY logical_workflow_reusable_call_result_jobs
    ADD CONSTRAINT logical_workflow_reusable_call_result_jobs_order_unique UNIQUE (run_id, parent_invocation_id, caller_logical_job_id, source_order);

ALTER TABLE ONLY logical_workflow_reusable_call_result_jobs
    ADD CONSTRAINT logical_workflow_reusable_call_result_jobs_pk PRIMARY KEY (run_id, parent_invocation_id, caller_logical_job_id, child_logical_job_id);

ALTER TABLE ONLY logical_workflow_reusable_call_result_outputs
    ADD CONSTRAINT logical_workflow_reusable_call_result_outputs_order_unique UNIQUE (run_id, parent_invocation_id, caller_logical_job_id, source_order);

ALTER TABLE ONLY logical_workflow_reusable_call_result_outputs
    ADD CONSTRAINT logical_workflow_reusable_call_result_outputs_pk PRIMARY KEY (run_id, parent_invocation_id, caller_logical_job_id, callee_output_name);

ALTER TABLE ONLY logical_workflow_reusable_call_results
    ADD CONSTRAINT logical_workflow_reusable_call_results_child_unique UNIQUE (run_id, child_invocation_id);

ALTER TABLE ONLY logical_workflow_reusable_call_results
    ADD CONSTRAINT logical_workflow_reusable_call_results_instance_unique UNIQUE (caller_instance_id);

ALTER TABLE ONLY logical_workflow_reusable_call_results
    ADD CONSTRAINT logical_workflow_reusable_call_results_pk PRIMARY KEY (run_id, parent_invocation_id, caller_logical_job_id);

ALTER TABLE ONLY logical_workflow_reusable_workflow_catalog
    ADD CONSTRAINT logical_workflow_reusable_catalog_exact_unique UNIQUE (run_id, catalog_entry_id, source_digest, plan_digest);

ALTER TABLE ONLY logical_workflow_reusable_workflow_catalog
    ADD CONSTRAINT logical_workflow_reusable_catalog_path_unique UNIQUE (run_id, workflow_path);

ALTER TABLE ONLY logical_workflow_reusable_workflow_catalog
    ADD CONSTRAINT logical_workflow_reusable_catalog_pk PRIMARY KEY (run_id, catalog_entry_id);

ALTER TABLE ONLY logical_workflow_reusable_expanded_dependencies
    ADD CONSTRAINT logical_workflow_reusable_expanded_dependencies_pk PRIMARY KEY (run_id, invocation_id, logical_job_id, prerequisite_job_id);

ALTER TABLE ONLY logical_workflow_reusable_expanded_jobs
    ADD CONSTRAINT logical_workflow_reusable_expanded_jobs_key_unique UNIQUE (run_id, invocation_id, logical_key);

ALTER TABLE ONLY logical_workflow_reusable_expanded_jobs
    ADD CONSTRAINT logical_workflow_reusable_expanded_jobs_order_unique UNIQUE (run_id, invocation_id, source_order);

ALTER TABLE ONLY logical_workflow_reusable_expanded_jobs
    ADD CONSTRAINT logical_workflow_reusable_expanded_jobs_pk PRIMARY KEY (run_id, invocation_id, logical_job_id);

ALTER TABLE ONLY logical_workflow_reusable_invocation_expansions
    ADD CONSTRAINT logical_workflow_reusable_expansion_runtime_exact UNIQUE (run_id, parent_invocation_id, caller_logical_job_id, invocation_id);

ALTER TABLE ONLY logical_workflow_reusable_invocation_expansions
    ADD CONSTRAINT logical_workflow_reusable_expansions_callsite_unique UNIQUE (run_id, parent_invocation_id, caller_logical_job_id);

ALTER TABLE ONLY logical_workflow_reusable_invocation_expansions
    ADD CONSTRAINT logical_workflow_reusable_expansions_pk PRIMARY KEY (run_id, invocation_id);

ALTER TABLE ONLY logical_workflow_reusable_input_bindings
    ADD CONSTRAINT logical_workflow_reusable_input_bindings_order_unique UNIQUE (run_id, invocation_id, source_order);

ALTER TABLE ONLY logical_workflow_reusable_input_bindings
    ADD CONSTRAINT logical_workflow_reusable_input_bindings_pk PRIMARY KEY (run_id, invocation_id, input_key);

ALTER TABLE ONLY logical_workflow_reusable_outputs
    ADD CONSTRAINT logical_workflow_reusable_outputs_order_unique UNIQUE (run_id, invocation_id, source_order);

ALTER TABLE ONLY logical_workflow_reusable_outputs
    ADD CONSTRAINT logical_workflow_reusable_outputs_pk PRIMARY KEY (run_id, invocation_id, output_key);

ALTER TABLE ONLY logical_workflow_reusable_permission_grants
    ADD CONSTRAINT logical_workflow_reusable_permission_grants_pk PRIMARY KEY (run_id, invocation_id, permission_name);

ALTER TABLE ONLY logical_workflow_reusable_permission_snapshots
    ADD CONSTRAINT logical_workflow_reusable_permission_snapshots_pk PRIMARY KEY (run_id, invocation_id);

ALTER TABLE ONLY logical_workflow_reusable_secret_bindings
    ADD CONSTRAINT logical_workflow_reusable_secret_bindings_order_unique UNIQUE (run_id, invocation_id, source_order);

ALTER TABLE ONLY logical_workflow_reusable_secret_bindings
    ADD CONSTRAINT logical_workflow_reusable_secret_bindings_pk PRIMARY KEY (run_id, invocation_id, target_name);

ALTER TABLE ONLY logical_workflow_reusable_workflow_runs
    ADD CONSTRAINT logical_workflow_reusable_workflow_runs_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY logical_workflow_run_result_claims
    ADD CONSTRAINT logical_workflow_run_result_claims_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY logical_workflow_run_result_claims
    ADD CONSTRAINT logical_workflow_run_result_claims_target_unique UNIQUE (run_id, root_invocation_id);

ALTER TABLE ONLY logical_workflow_run_result_jobs
    ADD CONSTRAINT logical_workflow_run_result_jobs_pkey PRIMARY KEY (run_id, logical_job_id);

ALTER TABLE ONLY logical_workflow_run_result_jobs
    ADD CONSTRAINT logical_workflow_run_result_jobs_run_id_logical_key_key UNIQUE (run_id, logical_key);

ALTER TABLE ONLY logical_workflow_run_result_jobs
    ADD CONSTRAINT logical_workflow_run_result_jobs_run_id_source_order_key UNIQUE (run_id, source_order);

ALTER TABLE ONLY logical_workflow_run_results
    ADD CONSTRAINT logical_workflow_run_results_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY logical_workflow_run_results
    ADD CONSTRAINT logical_workflow_run_results_target_unique UNIQUE (run_id, root_invocation_id);

ALTER TABLE ONLY logical_workflow_runs
    ADD CONSTRAINT logical_workflow_runs_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY logical_workflow_runtime_policy_pins
    ADD CONSTRAINT logical_workflow_runtime_policy_pins_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY logical_workflow_work_selection_replay_horizons
    ADD CONSTRAINT logical_workflow_work_selection_replay_horizons_pkey PRIMARY KEY (queue_name);

ALTER TABLE ONLY workflow_rerun_attempt_jobs
    ADD CONSTRAINT workflow_rerun_attempt_jobs_exact_unique UNIQUE (run_id, source_run_id, logical_job_id, source_logical_job_id);

ALTER TABLE ONLY workflow_rerun_attempt_jobs
    ADD CONSTRAINT workflow_rerun_attempt_jobs_pkey PRIMARY KEY (run_id, logical_job_id);

ALTER TABLE ONLY workflow_rerun_attempt_jobs
    ADD CONSTRAINT workflow_rerun_attempt_jobs_source_unique UNIQUE (run_id, source_logical_job_id);

ALTER TABLE ONLY workflow_rerun_attempts
    ADD CONSTRAINT workflow_rerun_attempts_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY workflow_rerun_attempts
    ADD CONSTRAINT workflow_rerun_attempts_root_attempt_unique UNIQUE (root_run_id, attempt);

ALTER TABLE ONLY workflow_rerun_attempts
    ADD CONSTRAINT workflow_rerun_attempts_run_source_unique UNIQUE (run_id, source_run_id);

ALTER TABLE ONLY workflow_rerun_audit_evidence
    ADD CONSTRAINT workflow_rerun_audit_evidence_event_id_key UNIQUE (event_id);

ALTER TABLE ONLY workflow_rerun_audit_evidence
    ADD CONSTRAINT workflow_rerun_audit_evidence_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY workflow_rerun_carried_job_outputs
    ADD CONSTRAINT workflow_rerun_carried_job_outputs_pkey PRIMARY KEY (logical_job_id, output_name);

ALTER TABLE ONLY workflow_rerun_carried_job_results
    ADD CONSTRAINT workflow_rerun_carried_job_results_pkey PRIMARY KEY (logical_job_id);

ALTER TABLE ONLY workflow_rerun_carried_job_results
    ADD CONSTRAINT workflow_rerun_carried_job_results_source_unique UNIQUE (run_id, source_logical_job_id);

ALTER TABLE ONLY workflow_rerun_carried_job_results
    ADD CONSTRAINT workflow_rerun_carried_job_results_target_unique UNIQUE (run_id, invocation_id, logical_job_id);

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_exact_subject_unique UNIQUE (tenant_id, run_id, github_check_subject_id);

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_github_check_subject_id_key UNIQUE (github_check_subject_id);

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_operation_run_unique UNIQUE (tenant_id, operation_id, rerun_run_id);

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_pkey PRIMARY KEY (tenant_id, operation_id);

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_tenant_run_unique UNIQUE (tenant_id, rerun_run_id);

ALTER TABLE ONLY workflow_run_number_counters
    ADD CONSTRAINT workflow_run_number_counters_pkey PRIMARY KEY (workflow_id);

ALTER TABLE ONLY workflow_runs
    ADD CONSTRAINT workflow_runs_id_alias_unique UNIQUE (run_id_alias);

ALTER TABLE ONLY workflow_runs
    ADD CONSTRAINT workflow_runs_number_attempt_unique UNIQUE (workflow_id, run_number, run_attempt);

ALTER TABLE ONLY workflow_runs
    ADD CONSTRAINT workflow_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workflow_runs
    ADD CONSTRAINT workflow_runs_repository_id_unique UNIQUE (repository_id, id);

ALTER TABLE ONLY workflow_runtime_policy_current
    ADD CONSTRAINT workflow_runtime_policy_current_pk PRIMARY KEY (tenant_id, repository_id);

ALTER TABLE ONLY workflow_runtime_policy_features
    ADD CONSTRAINT workflow_runtime_policy_features_pk PRIMARY KEY (tenant_id, repository_id, policy_revision, selector, feature);

ALTER TABLE ONLY workflow_runtime_policy_mappings
    ADD CONSTRAINT workflow_runtime_policy_mappings_pk PRIMARY KEY (tenant_id, repository_id, policy_revision, selector);

ALTER TABLE ONLY workflow_runtime_policy_revisions
    ADD CONSTRAINT workflow_runtime_policy_revisions_exact_unique UNIQUE (tenant_id, repository_id, policy_revision, policy_digest);

ALTER TABLE ONLY workflow_runtime_policy_revisions
    ADD CONSTRAINT workflow_runtime_policy_revisions_pk PRIMARY KEY (tenant_id, repository_id, policy_revision);

ALTER TABLE ONLY workflow_snapshots
    ADD CONSTRAINT workflow_snapshots_digest_unique UNIQUE (workflow_id, source_digest);

ALTER TABLE ONLY workflow_snapshots
    ADD CONSTRAINT workflow_snapshots_id_workflow_unique UNIQUE (id, workflow_id);

ALTER TABLE ONLY workflow_snapshots
    ADD CONSTRAINT workflow_snapshots_pkey PRIMARY KEY (id);

ALTER TABLE ONLY workflow_variable_versions
    ADD CONSTRAINT workflow_variable_versions_identity UNIQUE (tenant_id, id, variable_id, version_number);

ALTER TABLE ONLY workflow_variable_versions
    ADD CONSTRAINT workflow_variable_versions_number_unique UNIQUE (tenant_id, variable_id, version_number);

ALTER TABLE ONLY workflow_variable_versions
    ADD CONSTRAINT workflow_variable_versions_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY workflow_variables
    ADD CONSTRAINT workflow_variables_primary_key PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY workflow_variables
    ADD CONSTRAINT workflow_variables_scope_identity UNIQUE (tenant_id, id, repository_id, environment_id, scope_kind);
