CREATE UNIQUE INDEX attempt_log_segments_one_terminal ON attempt_log_segments USING btree (stream_id) WHERE end_of_stream;

CREATE UNIQUE INDEX attempt_terminal_results_logical_workflow_order_unique ON attempt_terminal_results USING btree (logical_workflow_logical_job_id, logical_workflow_terminal_ordinal) WHERE (logical_workflow_logical_job_id IS NOT NULL);

CREATE INDEX concurrency_group_pending_runs_order ON concurrency_group_pending_runs USING btree (repository_id, normalized_key, queue_sequence);

CREATE INDEX gha_cache_attempt ON github_actions_cache_entries USING btree (job_id, attempt_id, fencing_token);

CREATE INDEX gha_cache_lookup ON github_actions_cache_entries USING btree (repository_id, cache_ref, cache_version, cache_key text_pattern_ops, finalized_at_seconds DESC, id) WHERE (state = 'finalized'::text);

CREATE INDEX gha_cache_retention ON github_actions_cache_entries USING btree (repository_id, state, last_accessed_at_seconds, finalized_at_seconds, id);

CREATE UNIQUE INDEX github_check_projection_external_run_unique ON github_check_projection_outbox USING btree (external_run_id) WHERE (external_run_id IS NOT NULL);

CREATE INDEX github_check_projection_outbox_eligible ON github_check_projection_outbox USING btree (state, next_attempt_at_ms, next_reconcile_at_ms, state_updated_at_ms, subject_id) WHERE (state = ANY (ARRAY['pending'::text, 'retry'::text, 'create_indeterminate'::text, 'claimed'::text]));

CREATE INDEX github_check_subjects_run ON github_check_subjects USING btree (tenant_id, repository_id, workflow_run_id) WHERE (workflow_run_id IS NOT NULL);

CREATE INDEX github_membership_snapshots_current ON github_membership_snapshots USING btree (tenant_id, principal_id, provider_id, valid_until_ms DESC, observed_at_ms DESC);

CREATE INDEX github_oidc_key_deadlines_active_lookup ON github_oidc_key_deadlines USING btree (key_use, max_not_after_seconds, key_id);

CREATE UNIQUE INDEX github_role_mappings_active_organization_repository ON github_role_mappings USING btree (tenant_id, provider_id, organization_id, role_id, repository_id) WHERE ((status = 'active'::text) AND (team_id IS NULL) AND (scope_kind = 'repository'::text));

CREATE UNIQUE INDEX github_role_mappings_active_organization_runner_group ON github_role_mappings USING btree (tenant_id, provider_id, organization_id, role_id, runner_group_id) WHERE ((status = 'active'::text) AND (team_id IS NULL) AND (scope_kind = 'runner_group'::text));

CREATE UNIQUE INDEX github_role_mappings_active_organization_tenant ON github_role_mappings USING btree (tenant_id, provider_id, organization_id, role_id) WHERE ((status = 'active'::text) AND (team_id IS NULL) AND (scope_kind = 'tenant'::text));

CREATE UNIQUE INDEX github_role_mappings_active_team_repository ON github_role_mappings USING btree (tenant_id, provider_id, organization_id, team_id, role_id, repository_id) WHERE ((status = 'active'::text) AND (team_id IS NOT NULL) AND (scope_kind = 'repository'::text));

CREATE UNIQUE INDEX github_role_mappings_active_team_runner_group ON github_role_mappings USING btree (tenant_id, provider_id, organization_id, team_id, role_id, runner_group_id) WHERE ((status = 'active'::text) AND (team_id IS NOT NULL) AND (scope_kind = 'runner_group'::text));

CREATE UNIQUE INDEX github_role_mappings_active_team_tenant ON github_role_mappings USING btree (tenant_id, provider_id, organization_id, team_id, role_id) WHERE ((status = 'active'::text) AND (team_id IS NOT NULL) AND (scope_kind = 'tenant'::text));

CREATE INDEX github_runtime_authority_expired_mint_claims ON github_runtime_authority_issuances USING btree (mint_claim_expires_at_ms, requested_at_ms, attempt_id) WHERE (state = 'claimed'::text);

CREATE INDEX github_runtime_authority_mint_deadlines ON github_runtime_authority_issuances USING btree (request_deadline_at_ms, attempt_id) WHERE (state = 'minting'::text);

CREATE INDEX github_runtime_authority_mint_retry_ready ON github_runtime_authority_issuances USING btree (next_mint_at_ms, attempt_id, fencing_token) WHERE (state = 'mint_retry_pending'::text);

CREATE UNIQUE INDEX github_runtime_authority_revoke_owner_unique ON github_runtime_authority_issuances USING btree (revoke_claim_owner_id) WHERE (revoke_claim_owner_id IS NOT NULL);

CREATE INDEX github_runtime_authority_revoke_ready ON github_runtime_authority_issuances USING btree (COALESCE(next_revoke_at_ms, revoke_claim_expires_at_ms), revoke_pending_at_ms, attempt_id) WHERE (state = 'revoke_pending'::text);

CREATE INDEX github_runtime_authority_safe_erasure ON github_runtime_authority_issuances USING btree (safe_erase_after_ms, attempt_id, fencing_token) WHERE (state = ANY (ARRAY['ready'::text, 'revoke_pending'::text, 'quarantined'::text]));

CREATE UNIQUE INDEX github_schedule_discovery_claims_one_live_repository ON github_schedule_discovery_claims USING btree (tenant_id, repository_id, provider_connection_id) WHERE (state = 'claimed'::text);

CREATE INDEX github_schedule_fires_claimable ON github_schedule_fires USING btree (next_attempt_at_ms, scheduled_at_ms, fire_id) WHERE (state = ANY (ARRAY['pending'::text, 'claimed'::text]));

CREATE INDEX github_schedule_runtime_due ON github_schedule_runtime USING btree (next_fire_at_ms, tenant_id, repository_id, provider_connection_id, entry_ordinal);

CREATE INDEX github_server_service_authorities_bootstrap_due ON github_server_service_authorities USING btree (tenant_id, state_updated_at_ms, id, next_issuance_generation) WHERE ((state = 'active'::text) AND (current_issuance_generation IS NULL) AND (refresh_issuance_generation IS NULL));

CREATE INDEX github_server_service_handoffs_live_issuance ON github_server_service_authority_handoffs USING btree (authority_id, generation, required_through_ms) WHERE (released_at_ms IS NULL);

CREATE INDEX github_server_service_issuances_erase_due ON github_server_service_authority_issuances USING btree (tenant_id, safe_erase_after_ms, authority_id, generation) WHERE (state = ANY (ARRAY['ready'::text, 'indeterminate'::text, 'revoke_pending'::text, 'revoke_claimed'::text, 'revoke_retry'::text, 'quarantined'::text]));

CREATE INDEX github_server_service_issuances_mint_claim_due ON github_server_service_authority_issuances USING btree (tenant_id, LEAST(mint_claim_expires_at_ms, request_deadline_at_ms), authority_id, generation) WHERE (state = ANY (ARRAY['claimed'::text, 'minting'::text]));

CREATE INDEX github_server_service_issuances_mint_retry_deadline_due ON github_server_service_authority_issuances USING btree (tenant_id, request_deadline_at_ms, authority_id, generation) WHERE (state = 'mint_retry'::text);

CREATE INDEX github_server_service_issuances_mint_retry_due ON github_server_service_authority_issuances USING btree (tenant_id, next_mint_at_ms, authority_id, generation) WHERE (state = 'mint_retry'::text);

CREATE INDEX github_server_service_issuances_ready_refresh_due ON github_server_service_authority_issuances USING btree (tenant_id, (((provider_expires_at_ms)::numeric - (1680000)::numeric)), authority_id, generation) WHERE (state = 'ready'::text);

CREATE INDEX github_server_service_issuances_revoke_claim_due ON github_server_service_authority_issuances USING btree (tenant_id, revoke_claim_expires_at_ms, authority_id, generation) WHERE (state = 'revoke_claimed'::text);

CREATE INDEX github_server_service_issuances_revoke_pending_due ON github_server_service_authority_issuances USING btree (tenant_id, state_updated_at_ms, authority_id, generation) WHERE (state = 'revoke_pending'::text);

CREATE INDEX github_server_service_issuances_revoke_retry_due ON github_server_service_authority_issuances USING btree (tenant_id, next_revoke_at_ms, authority_id, generation) WHERE (state = 'revoke_retry'::text);

CREATE INDEX human_login_transactions_device_poll ON human_login_transactions USING btree (next_poll_at_ms, id) WHERE ((flow_kind = 'device'::text) AND (status = 'pending'::text));

CREATE INDEX human_login_transactions_expiry ON human_login_transactions USING btree (expires_at_ms, id) WHERE (status = 'pending'::text);

CREATE UNIQUE INDEX human_login_transactions_live_browser_state ON human_login_transactions USING btree (provider_id, state_hash_key_id, state_hash) WHERE ((flow_kind = 'browser'::text) AND (status = 'pending'::text));

CREATE UNIQUE INDEX human_login_transactions_live_poll_proof ON human_login_transactions USING btree (poll_proof_hash_key_id, poll_proof_hash) WHERE ((flow_kind = 'device'::text) AND (status = 'pending'::text));

CREATE INDEX human_provider_identities_login_lookup ON human_provider_identities USING btree (provider_id, normalized_login);

CREATE UNIQUE INDEX human_provider_tokens_one_active_identity ON human_provider_tokens USING btree (tenant_id, provider_id, provider_subject) WHERE (revoked_at_ms IS NULL);

CREATE INDEX human_provider_tokens_refresh_due ON human_provider_tokens USING btree (access_expires_at_ms, tenant_id, provider_id, provider_subject) WHERE ((revoked_at_ms IS NULL) AND (access_expires_at_ms IS NOT NULL));

CREATE INDEX human_sessions_active_token_lookup ON human_sessions USING btree (token_hash_key_id, token_hash, expires_at_ms) WHERE ((revoked_at_ms IS NULL) AND (lifecycle_status = 'active'::text));

CREATE INDEX human_sessions_expiry ON human_sessions USING btree (expires_at_ms, id) WHERE (revoked_at_ms IS NULL);

CREATE INDEX human_sessions_pending_activation_expiry ON human_sessions USING btree (activation_deadline_ms, id) WHERE ((lifecycle_status = 'pending_activation'::text) AND (revoked_at_ms IS NULL));

CREATE INDEX human_sessions_principal_activity ON human_sessions USING btree (tenant_id, principal_id, issued_at_ms DESC, id) WHERE (revoked_at_ms IS NULL);

CREATE UNIQUE INDEX job_attempts_active_lease_unique ON job_attempts USING btree (lease_id) WHERE (lease_id IS NOT NULL);

CREATE INDEX job_attempts_expiring_leases ON job_attempts USING btree (lease_expires_at_ms, id) WHERE (lifecycle = ANY (ARRAY['leased'::text, 'preparing'::text, 'running'::text, 'cancelling'::text, 'finalizing'::text]));

CREATE UNIQUE INDEX job_attempts_live_runner_slot_unique ON job_attempts USING btree (runner_id, runner_slot) WHERE (lease_id IS NOT NULL);

CREATE UNIQUE INDEX job_attempts_one_current_per_job ON job_attempts USING btree (job_id) WHERE (lifecycle = ANY (ARRAY['queued'::text, 'leased'::text, 'preparing'::text, 'running'::text, 'cancelling'::text, 'finalizing'::text]));

CREATE INDEX job_attempts_queue_order ON job_attempts USING btree (queued_at_ms, id) WHERE (lifecycle = 'queued'::text);

CREATE INDEX job_dependencies_prerequisites ON job_dependencies USING btree (run_id, prerequisite_job_id, job_id);

CREATE INDEX job_environment_gates_waiting ON job_environment_gates USING btree (tenant_id, state, updated_at_ms, attempt_id) WHERE (state = ANY (ARRAY['selection_pending'::text, 'waiting'::text, 'resolving'::text]));

CREATE INDEX managed_secret_delivery_operations_pending ON managed_secret_delivery_operations USING btree (tenant_id, usable_until_ms, operation_id) WHERE (state = 'pending'::text);

CREATE INDEX protected_environment_approval_requests_pending ON protected_environment_approval_requests USING btree (tenant_id, repository_id, environment_id, created_at_ms, id) WHERE (status = 'pending'::text);

CREATE INDEX provider_delivery_inbox_expired_claim ON provider_delivery_inbox USING btree (claim_expires_at_ms, accepted_at_ms, id) WHERE (state = 'claimed'::text);

CREATE INDEX provider_delivery_inbox_ready ON provider_delivery_inbox USING btree (COALESCE(next_attempt_at_ms, accepted_at_ms), accepted_at_ms, id) WHERE (state = ANY (ARRAY['pending'::text, 'retry'::text]));

CREATE UNIQUE INDEX rbac_role_bindings_active_repository_grant ON rbac_role_bindings USING btree (tenant_id, principal_id, role_id, repository_id) WHERE ((status = 'active'::text) AND (scope_kind = 'repository'::text));

CREATE UNIQUE INDEX rbac_role_bindings_active_runner_group_grant ON rbac_role_bindings USING btree (tenant_id, principal_id, role_id, runner_group_id) WHERE ((status = 'active'::text) AND (scope_kind = 'runner_group'::text));

CREATE UNIQUE INDEX rbac_role_bindings_active_tenant_grant ON rbac_role_bindings USING btree (tenant_id, principal_id, role_id) WHERE ((status = 'active'::text) AND (scope_kind = 'tenant'::text));

CREATE INDEX rbac_role_bindings_effective_principal ON rbac_role_bindings USING btree (tenant_id, principal_id, scope_kind, valid_until_ms) WHERE (status = 'active'::text);

CREATE UNIQUE INDEX repositories_provider_owner_name_unique ON repositories USING btree (tenant_id, scm_provider, lower(owner), lower(name));

CREATE UNIQUE INDEX runner_lease_offer_publications_lease ON runner_lease_offer_publications USING btree (attempt_id, lease_id, fencing_token);

CREATE INDEX runner_machine_certificates_active_by_runner ON runner_machine_certificates USING btree (runner_id, expires_at_seconds) WHERE (revoked_at_seconds IS NULL);

CREATE INDEX runner_machine_certificates_revoked_at ON runner_machine_certificates USING btree (revoked_at_seconds) WHERE (revoked_at_seconds IS NOT NULL);

CREATE INDEX runner_enrollment_tokens_active ON runner_enrollment_tokens USING btree (expires_at_ms, id) WHERE (consumed_at_ms IS NULL);

CREATE INDEX runner_operation_receipts_attempt ON runner_operation_receipts USING btree (requested_attempt_id, completed_at_ms);

CREATE UNIQUE INDEX runner_sessions_one_live_per_runner ON runner_sessions USING btree (runner_id) WHERE (disconnected_at_ms IS NULL);

CREATE INDEX secret_cleanup_outbox_ready ON secret_cleanup_outbox USING btree (next_attempt_at_ms, sequence) WHERE (status = 'pending'::text);

CREATE INDEX secret_custody_active_provider_scan ON secret_providers USING btree (tenant_id, provider_id) WHERE (status = 'active'::text);

CREATE INDEX secret_custody_builtin_version_key_scan ON secret_version_envelopes USING btree (wrapping_key_id, tenant_id, secret_version_id, envelope_generation);

CREATE INDEX secret_custody_configuration_key_scan ON secret_provider_configuration_envelopes USING btree (wrapping_key_id COLLATE "C", tenant_id, provider_id, envelope_generation);

CREATE INDEX secret_custody_lease_key_scan ON secret_provider_lease_envelopes USING btree (wrapping_key_id COLLATE "C", tenant_id, provider_lease_record_id, envelope_generation);

CREATE INDEX secret_custody_locator_key_scan ON secret_provider_locator_envelopes USING btree (wrapping_key_id COLLATE "C", tenant_id, secret_id, envelope_generation);

CREATE INDEX secret_custody_open_cleanup_scan ON secret_cleanup_outbox USING btree (sequence) WHERE (status = ANY (ARRAY['pending'::text, 'in_progress'::text, 'dead_letter'::text]));

CREATE INDEX secret_custody_open_lease_scan ON secret_provider_leases USING btree (tenant_id, id) WHERE (status = ANY (ARRAY['active'::text, 'revocation_pending'::text]));

CREATE INDEX secret_custody_open_mutation_scan ON secret_version_mutations USING btree (tenant_id, mutation_id) WHERE (state = 'reserved'::text);

CREATE INDEX secret_custody_open_recovery_scan ON secret_mutation_recovery_outbox USING btree (sequence) WHERE (status = ANY (ARRAY['pending'::text, 'in_progress'::text]));

CREATE INDEX secret_custody_open_rotation_item_scan ON secret_key_rotation_items USING btree (tenant_id, rotation_id) WHERE (status = ANY (ARRAY['pending'::text, 'failed'::text]));

CREATE INDEX secret_custody_open_rotation_scan ON secret_key_rotations USING btree (tenant_id, id) WHERE (status = ANY (ARRAY['pending'::text, 'running'::text, 'failed'::text]));

CREATE INDEX secret_custody_provider_version_key_scan ON secret_provider_version_envelopes USING btree (wrapping_key_id COLLATE "C", tenant_id, secret_version_id, envelope_generation);

CREATE INDEX secret_custody_rotation_from_key_scan ON secret_key_rotations USING btree (from_wrapping_key_id COLLATE "C", tenant_id, id);

CREATE INDEX secret_custody_rotation_to_key_scan ON secret_key_rotations USING btree (to_wrapping_key_id COLLATE "C", tenant_id, id);

CREATE UNIQUE INDEX secret_key_rotations_one_active_provider ON secret_key_rotations USING btree (tenant_id, provider_id) WHERE (status = ANY (ARRAY['pending'::text, 'running'::text]));

CREATE INDEX secret_mutation_recovery_outbox_ready ON secret_mutation_recovery_outbox USING btree (next_attempt_at_ms, sequence) WHERE (status = ANY (ARRAY['pending'::text, 'in_progress'::text]));

CREATE INDEX secret_provider_leases_expiry ON secret_provider_leases USING btree (expires_at_seconds, tenant_id, id) WHERE (status = ANY (ARRAY['active'::text, 'revocation_pending'::text]));

CREATE UNIQUE INDEX secret_providers_one_default ON secret_providers USING btree (tenant_id) WHERE is_default;

CREATE UNIQUE INDEX secret_version_lifecycle_destroy_request_unique ON secret_version_lifecycle USING btree (tenant_id, provider_id, destroy_request_id) WHERE (destroy_request_id IS NOT NULL);

CREATE UNIQUE INDEX secret_version_lifecycle_one_staged_candidate ON secret_version_lifecycle USING btree (tenant_id, secret_id) WHERE (status = 'staged'::text);

CREATE UNIQUE INDEX secret_version_mutations_one_committed_version ON secret_version_mutations USING btree (tenant_id, committed_version_id) WHERE (committed_version_id IS NOT NULL);

CREATE UNIQUE INDEX secret_version_mutations_one_create ON secret_version_mutations USING btree (tenant_id, secret_id) WHERE (mutation_kind = 'create'::text);

CREATE INDEX secret_version_mutations_reserved ON secret_version_mutations USING btree (tenant_id, secret_id, reserved_at_ms, mutation_id) WHERE (state = 'reserved'::text);

CREATE INDEX secret_workload_grants_active_attempt ON secret_workload_grants USING btree (tenant_id, attempt_id, expires_at_ms, id) WHERE (status = 'active'::text);

CREATE UNIQUE INDEX secrets_live_environment_name ON secrets USING btree (tenant_id, repository_id, environment_id, canonical_name) WHERE ((status <> 'deleted'::text) AND (scope_kind = 'environment'::text));

CREATE UNIQUE INDEX secrets_live_repository_name ON secrets USING btree (tenant_id, repository_id, canonical_name) WHERE ((status <> 'deleted'::text) AND (scope_kind = 'repository'::text));

CREATE UNIQUE INDEX secrets_live_tenant_name ON secrets USING btree (tenant_id, canonical_name) WHERE ((status <> 'deleted'::text) AND (scope_kind = 'tenant'::text));

CREATE INDEX security_audit_events_actor_time ON security_audit_events USING btree (tenant_id, actor_principal_id, occurred_at_ms DESC, sequence DESC) WHERE (actor_principal_id IS NOT NULL);

CREATE INDEX security_audit_events_tenant_time ON security_audit_events USING btree (tenant_id, occurred_at_ms DESC, sequence DESC);

CREATE UNIQUE INDEX security_audit_events_workflow_dispatch_target ON security_audit_events USING btree (tenant_id, resource_id) WHERE ((action = 'workflow.dispatch'::text) AND (resource_kind = 'workflow_run'::text));

CREATE UNIQUE INDEX security_audit_events_workflow_rerun_target ON security_audit_events USING btree (tenant_id, resource_id) WHERE ((action = 'workflow.rerun'::text) AND (resource_kind = 'workflow_run'::text));

CREATE INDEX tenant_human_memberships_principal ON tenant_human_memberships USING btree (principal_id, tenant_id);

CREATE UNIQUE INDEX workflow_admission_receipts_run ON workflow_admission_receipts USING btree (run_id) WHERE (run_id IS NOT NULL);

CREATE INDEX workflow_artifacts_expiry ON workflow_artifacts USING btree (expires_at_seconds, id) WHERE (expires_at_seconds IS NOT NULL);

CREATE INDEX workflow_artifacts_job_attempt ON workflow_artifacts USING btree (job_id, attempt_id, fencing_token);

CREATE INDEX logical_workflow_activation_preparation_claims_expired ON logical_workflow_activation_preparation_claims USING btree (expires_at_ms, run_id, invocation_id, logical_job_id) WHERE (state = 'preparing'::text);

CREATE INDEX logical_workflow_activation_selection_expiry ON logical_workflow_activation_work_selections USING btree (expires_at_ms, requested_at_ms, selection_id) WHERE (outcome <> 'selecting'::text);

CREATE UNIQUE INDEX logical_workflow_activation_selection_generation ON logical_workflow_activation_work_selections USING btree (logical_job_id, authority_kind, generation) WHERE (outcome = 'claimed'::text);

CREATE INDEX logical_workflow_activation_selection_target ON logical_workflow_activation_work_selections USING btree (logical_job_id, expires_at_ms, selection_id) WHERE (outcome = 'claimed'::text);

CREATE INDEX logical_workflow_dependencies_prerequisites ON logical_workflow_dependencies USING btree (run_id, invocation_id, prerequisite_job_id, logical_job_id);

CREATE INDEX logical_workflow_instance_result_claims_expired ON logical_workflow_instance_result_claims USING btree (expires_at_ms, run_id, invocation_id, logical_job_id, instance_id) WHERE (state = 'projecting'::text);

CREATE INDEX logical_workflow_instance_result_due_next ON logical_workflow_instance_result_due USING btree (available_at_ms, ready_at_ms, run_id, invocation_id, source_order, logical_job_id, attempt_id);

CREATE INDEX logical_workflow_instance_result_selections_expired_receipts ON logical_workflow_instance_result_selections USING btree (expires_at_ms, selection_id);

CREATE UNIQUE INDEX logical_workflow_invocations_one_root_per_run ON logical_workflow_invocations USING btree (run_id) WHERE (invocation_kind = 'root'::text);

CREATE INDEX logical_workflow_job_result_claims_expired ON logical_workflow_job_result_claims USING btree (expires_at_ms, run_id, invocation_id, logical_job_id) WHERE (state = 'aggregating'::text);

CREATE INDEX logical_workflow_job_result_due_next ON logical_workflow_job_result_due USING btree (available_at_ms, ready_at_ms, run_id, invocation_id, source_order, logical_job_id);

CREATE INDEX logical_workflow_job_result_selections_expired_receipts ON logical_workflow_job_result_selections USING btree (expires_at_ms, selection_id);

CREATE INDEX logical_workflow_jobs_expired_claim ON logical_workflow_jobs USING btree (activation_expires_at_ms, run_id, id) WHERE (state = 'activating'::text);

CREATE INDEX logical_workflow_jobs_pending ON logical_workflow_jobs USING btree (created_at_ms, run_id, source_order, id) WHERE (state = 'pending'::text);

CREATE INDEX logical_workflow_materialization_claims_expired ON logical_workflow_materialization_claims USING btree (expires_at_ms, run_id, invocation_id, logical_job_id, instance_id) WHERE (state = 'materializing'::text);

CREATE INDEX logical_workflow_materialization_selection_expiry ON logical_workflow_materialization_work_selections USING btree (expires_at_ms, requested_at_ms, selection_id) WHERE (outcome <> 'selecting'::text);

CREATE UNIQUE INDEX logical_workflow_materialization_selection_generation ON logical_workflow_materialization_work_selections USING btree (instance_id, generation) WHERE (outcome = 'claimed'::text);

CREATE INDEX logical_workflow_materialization_selection_target ON logical_workflow_materialization_work_selections USING btree (instance_id, expires_at_ms, selection_id) WHERE (outcome = 'claimed'::text);

CREATE UNIQUE INDEX logical_workflow_reusable_expansions_one_root ON logical_workflow_reusable_invocation_expansions USING btree (run_id) WHERE (depth = 0);

CREATE INDEX logical_workflow_reusable_expansions_parent ON logical_workflow_reusable_invocation_expansions USING btree (run_id, parent_invocation_id, caller_logical_job_id) WHERE (depth > 0);

CREATE INDEX logical_workflow_run_result_claims_expired ON logical_workflow_run_result_claims USING btree (expires_at_ms, run_id) WHERE (state = 'aggregating'::text);

CREATE INDEX workflow_rerun_attempt_jobs_source ON workflow_rerun_attempt_jobs USING btree (source_run_id, source_logical_job_id);

CREATE INDEX workflow_rerun_attempts_source ON workflow_rerun_attempts USING btree (source_run_id) WHERE (source_run_id IS NOT NULL);

CREATE UNIQUE INDEX workflow_runs_public_id_attempt ON workflow_runs USING btree (workflow_id, public_run_id_alias, run_attempt);

CREATE INDEX workflow_runs_repository_created ON workflow_runs USING btree (repository_id, created_at_ms DESC, id DESC);

CREATE INDEX workflow_runs_repository_ref_created ON workflow_runs USING btree (repository_id, git_ref, created_at_ms DESC, id DESC) WHERE (git_ref IS NOT NULL);

CREATE INDEX workflow_runs_repository_status_created ON workflow_runs USING btree (repository_id, status, created_at_ms DESC, id DESC);

CREATE INDEX workflow_runs_repository_workflow_created ON workflow_runs USING btree (repository_id, workflow_id, created_at_ms DESC, id DESC);

CREATE INDEX workflow_runs_runnable_status ON workflow_runs USING btree (status, created_at_ms, id) WHERE (status = ANY (ARRAY['queued'::text, 'in_progress'::text]));

CREATE UNIQUE INDEX workflow_variables_live_environment_name ON workflow_variables USING btree (tenant_id, repository_id, environment_id, canonical_name) WHERE ((scope_kind = 'environment'::text) AND (status <> 'deleted'::text));

CREATE UNIQUE INDEX workflow_variables_live_repository_name ON workflow_variables USING btree (tenant_id, repository_id, canonical_name) WHERE ((scope_kind = 'repository'::text) AND (status <> 'deleted'::text));
