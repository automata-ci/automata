ALTER TABLE ONLY attempt_cancellation_intents
    ADD CONSTRAINT attempt_cancellation_delivery_command FOREIGN KEY (delivery_session_id, delivery_command_sequence) REFERENCES runner_command_outbox(runner_session_id, command_sequence) ON DELETE RESTRICT;

ALTER TABLE ONLY attempt_cancellation_intents
    ADD CONSTRAINT attempt_cancellation_intents_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES job_attempts(id) ON DELETE CASCADE;

ALTER TABLE ONLY attempt_log_segments
    ADD CONSTRAINT attempt_log_segments_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES attempt_log_streams(id) ON DELETE CASCADE;

ALTER TABLE ONLY attempt_log_streams
    ADD CONSTRAINT attempt_log_streams_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES job_attempts(id) ON DELETE CASCADE;

ALTER TABLE ONLY attempt_log_streams
    ADD CONSTRAINT attempt_log_streams_session_fence FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY attempt_terminal_results
    ADD CONSTRAINT attempt_terminal_results_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES job_attempts(id) ON DELETE CASCADE;

ALTER TABLE ONLY attempt_terminal_results
    ADD CONSTRAINT attempt_terminal_results_server_cancellation_intent_fk FOREIGN KEY (attempt_id, server_cancellation_operation_id) REFERENCES attempt_cancellation_intents(attempt_id, operation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY attempt_terminal_results
    ADD CONSTRAINT attempt_terminal_results_session_fence FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY concurrency_group_pending_runs
    ADD CONSTRAINT concurrency_group_pending_runs_group_fk FOREIGN KEY (repository_id, normalized_key) REFERENCES concurrency_groups(repository_id, normalized_key) ON DELETE CASCADE;

ALTER TABLE ONLY concurrency_group_pending_runs
    ADD CONSTRAINT concurrency_group_pending_runs_run_fk FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY concurrency_groups
    ADD CONSTRAINT concurrency_groups_repository_id_fkey FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE ONLY concurrency_groups
    ADD CONSTRAINT concurrency_groups_running_run_matches_repository FOREIGN KEY (repository_id, running_run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_actions_cache_entries
    ADD CONSTRAINT gha_cache_job_attempt FOREIGN KEY (job_id, attempt_id) REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_actions_cache_entries
    ADD CONSTRAINT gha_cache_repository_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_actions_cache_entries
    ADD CONSTRAINT gha_cache_run_job FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_actions_cache_entries
    ADD CONSTRAINT gha_cache_tenant_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_actions_cache_block_commits
    ADD CONSTRAINT github_actions_cache_block_commits_entry_id_fkey FOREIGN KEY (entry_id) REFERENCES github_actions_cache_entries(id) ON DELETE CASCADE;

ALTER TABLE ONLY github_actions_cache_blocks
    ADD CONSTRAINT github_actions_cache_blocks_entry_id_fkey FOREIGN KEY (entry_id) REFERENCES github_actions_cache_entries(id) ON DELETE CASCADE;

ALTER TABLE ONLY github_check_projection_outbox
    ADD CONSTRAINT github_check_projection_outbox_subject_id_fkey FOREIGN KEY (subject_id) REFERENCES github_check_subjects(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_check_annotation_progress
    ADD CONSTRAINT github_check_annotation_progress_subject_id_fkey FOREIGN KEY (subject_id) REFERENCES github_check_subjects(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_repository_run FOREIGN KEY (repository_id, workflow_run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_parent FOREIGN KEY (tenant_id, parent_subject_id) REFERENCES github_check_subjects(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_job FOREIGN KEY (workflow_run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_job_attempt FOREIGN KEY (job_attempt_id) REFERENCES job_attempts(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_schedule_fire FOREIGN KEY (tenant_id, repository_id, provider_connection_id, schedule_fire_id) REFERENCES github_schedule_fires(tenant_id, repository_id, provider_connection_id, fire_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_tenant_delivery FOREIGN KEY (provider_delivery_id, tenant_id) REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_tenant_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_check_subjects
    ADD CONSTRAINT github_check_subjects_workflow_rerun_run FOREIGN KEY (tenant_id, workflow_rerun_run_id) REFERENCES workflow_rerun_requests(tenant_id, rerun_run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_membership_snapshots
    ADD CONSTRAINT github_membership_snapshots_identity FOREIGN KEY (principal_id, provider_id, provider_subject) REFERENCES human_provider_identities(principal_id, provider_id, provider_subject) ON DELETE RESTRICT;

ALTER TABLE ONLY github_membership_snapshots
    ADD CONSTRAINT github_membership_snapshots_membership FOREIGN KEY (tenant_id, principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_concrete_job FOREIGN KEY (instance_id) REFERENCES logical_workflow_concrete_jobs(instance_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_job_attempt FOREIGN KEY (job_id, attempt_id) REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_repository_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_repository_workflow FOREIGN KEY (repository_id, workflow_id) REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_run_job FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_runner_session FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_signed_run_evidence FOREIGN KEY (repository_id, run_id, github_run_subject_evidence_sha256) REFERENCES github_workflow_run_subject_evidence(repository_id, run_id, subject_evidence_sha256) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_tenant_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_authorities
    ADD CONSTRAINT github_oidc_authorities_tenant_runner FOREIGN KEY (tenant_id, runner_id) REFERENCES runners(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_oidc_issuance_slots
    ADD CONSTRAINT github_oidc_issuance_slots_authority_id_fkey FOREIGN KEY (authority_id) REFERENCES github_oidc_authorities(authority_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_organization_membership_observations
    ADD CONSTRAINT github_organization_membership_observations_snapshot FOREIGN KEY (tenant_id, snapshot_id) REFERENCES github_membership_snapshots(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_check_subject FOREIGN KEY (tenant_id, github_check_subject_id) REFERENCES github_check_subjects(tenant_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_checks_authority FOREIGN KEY (tenant_id, checks_authority_id) REFERENCES github_server_service_authorities(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_inbox FOREIGN KEY (provider_delivery_id, tenant_id) REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_manifest FOREIGN KEY (tenant_id, repository_id, provider_connection_id, provider_manifest_revision, provider_manifest_digest) REFERENCES github_provider_manifest_revisions(tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) MATCH FULL ON DELETE RESTRICT;

ALTER TABLE ONLY github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_repository_contents_authority FOREIGN KEY (repository_contents_authority_id) REFERENCES github_server_service_authorities(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_provider_manifest_current
    ADD CONSTRAINT github_provider_manifest_current_exact_revision FOREIGN KEY (tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) REFERENCES github_provider_manifest_revisions(tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) ON DELETE RESTRICT;

ALTER TABLE ONLY github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_runtime_policy_fk FOREIGN KEY (tenant_id, repository_id, runtime_policy_revision, runtime_policy_digest) REFERENCES workflow_runtime_policy_revisions(tenant_id, repository_id, policy_revision, policy_digest) ON DELETE RESTRICT;

ALTER TABLE ONLY github_repository_dispatch_pending_evidence
    ADD CONSTRAINT github_repository_dispatch_pending_checks_authority FOREIGN KEY (tenant_id, checks_authority_id) REFERENCES github_server_service_authorities(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_repository_dispatch_pending_evidence
    ADD CONSTRAINT github_repository_dispatch_pending_inbox FOREIGN KEY (provider_delivery_id, tenant_id) REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_repository_dispatch_pending_evidence
    ADD CONSTRAINT github_repository_dispatch_pending_manifest FOREIGN KEY (tenant_id, repository_id, provider_connection_id, provider_manifest_revision, provider_manifest_digest) REFERENCES github_provider_manifest_revisions(tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) MATCH FULL ON DELETE RESTRICT;

ALTER TABLE ONLY github_repository_dispatch_pending_evidence
    ADD CONSTRAINT github_repository_dispatch_pending_contents_authority FOREIGN KEY (repository_contents_authority_id) REFERENCES github_server_service_authorities(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_role_mappings
    ADD CONSTRAINT github_role_mappings_creator_membership FOREIGN KEY (tenant_id, created_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_role_mappings
    ADD CONSTRAINT github_role_mappings_disabler_membership FOREIGN KEY (tenant_id, disabled_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_role_mappings
    ADD CONSTRAINT github_role_mappings_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_role_mappings
    ADD CONSTRAINT github_role_mappings_role FOREIGN KEY (tenant_id, role_id) REFERENCES rbac_roles(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_role_mappings
    ADD CONSTRAINT github_role_mappings_runner_group FOREIGN KEY (tenant_id, runner_group_id) REFERENCES runner_groups(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_issuances_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_job_attempt FOREIGN KEY (job_id, attempt_id) REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_lease_renewal_receipts
    ADD CONSTRAINT github_runtime_authority_lease_renewal_receipts_authority_fk FOREIGN KEY (attempt_id, fencing_token) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_mint_begins
    ADD CONSTRAINT github_runtime_authority_mint_begins_authority_fk FOREIGN KEY (attempt_id, fencing_token) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_mint_begins
    ADD CONSTRAINT github_runtime_authority_mint_begins_claim_fk FOREIGN KEY (attempt_id, fencing_token, claim_fence) REFERENCES github_runtime_authority_mint_claims(attempt_id, fencing_token, claim_fence) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_mint_begins
    ADD CONSTRAINT github_runtime_authority_mint_begins_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_mint_claims
    ADD CONSTRAINT github_runtime_authority_mint_claims_authority_fk FOREIGN KEY (attempt_id, fencing_token) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_mint_claims
    ADD CONSTRAINT github_runtime_authority_mint_claims_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_operation_receipts
    ADD CONSTRAINT github_runtime_authority_operation_receipts_authority_fk FOREIGN KEY (attempt_id, fencing_token) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_operation_receipts
    ADD CONSTRAINT github_runtime_authority_operation_receipts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_operation_transitions
    ADD CONSTRAINT github_runtime_authority_operation_transitions_authority_fk FOREIGN KEY (attempt_id, fencing_token) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_operation_transitions
    ADD CONSTRAINT github_runtime_authority_operation_transitions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_repository_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_revocation_claims
    ADD CONSTRAINT github_runtime_authority_revocation_claims_authority_fk FOREIGN KEY (attempt_id, fencing_token) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_revocation_claims
    ADD CONSTRAINT github_runtime_authority_revocation_claims_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_run_job FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_runner_session FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_selection_tail_receipts_fk_activation FOREIGN KEY (activation_selection_id) REFERENCES logical_workflow_activation_work_selections(selection_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_selection_tail_receipts_fk_materializa FOREIGN KEY (materialization_selection_id) REFERENCES logical_workflow_materialization_work_selections(selection_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_selection_tail_receipts_fk_preparation FOREIGN KEY (preparation_selection_id) REFERENCES logical_workflow_activation_work_selections(selection_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_tenant_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_tenant_runner FOREIGN KEY (tenant_id, runner_id) REFERENCES runners(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_discovery_claims
    ADD CONSTRAINT github_schedule_discovery_claims_completed_registry FOREIGN KEY (completed_registry_id) REFERENCES github_schedule_registry_revisions(registry_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_discovery_claims
    ADD CONSTRAINT github_schedule_discovery_claims_manifest FOREIGN KEY (tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) REFERENCES github_provider_manifest_revisions(tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_discovery_claims
    ADD CONSTRAINT github_schedule_discovery_claims_manifest_owner FOREIGN KEY (tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest, github_repository_owner_id) REFERENCES github_provider_manifest_revisions(tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest, github_repository_owner_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_discovery_claims
    ADD CONSTRAINT github_schedule_discovery_claims_repository_contents_authority FOREIGN KEY (repository_contents_authority_id) REFERENCES github_server_service_authorities(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_fire_attempts
    ADD CONSTRAINT github_schedule_fire_attempts_fire FOREIGN KEY (fire_id) REFERENCES github_schedule_fires(fire_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_fires
    ADD CONSTRAINT github_schedule_fires_entry FOREIGN KEY (registry_id, entry_ordinal) REFERENCES github_schedule_registry_entries(registry_id, ordinal) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_fires
    ADD CONSTRAINT github_schedule_fires_registry_identity FOREIGN KEY (tenant_id, repository_id, provider_connection_id, registry_id) REFERENCES github_schedule_registry_revisions(tenant_id, repository_id, provider_connection_id, registry_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_fires
    ADD CONSTRAINT github_schedule_fires_repository_run FOREIGN KEY (repository_id, workflow_run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_registry_current
    ADD CONSTRAINT github_schedule_registry_current_revision FOREIGN KEY (tenant_id, repository_id, provider_connection_id, registry_id) REFERENCES github_schedule_registry_revisions(tenant_id, repository_id, provider_connection_id, registry_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_registry_current
    ADD CONSTRAINT github_schedule_registry_current_seal FOREIGN KEY (registry_id) REFERENCES github_schedule_registry_seals(registry_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_registry_entries
    ADD CONSTRAINT github_schedule_registry_entries_registry FOREIGN KEY (registry_id) REFERENCES github_schedule_registry_revisions(registry_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_registry_revisions
    ADD CONSTRAINT github_schedule_registry_revisions_discovery FOREIGN KEY (discovery_id) REFERENCES github_schedule_discovery_claims(discovery_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_registry_revisions
    ADD CONSTRAINT github_schedule_registry_revisions_manifest FOREIGN KEY (tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) REFERENCES github_provider_manifest_revisions(tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_registry_revisions
    ADD CONSTRAINT github_schedule_registry_revisions_manifest_owner FOREIGN KEY (tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest, github_repository_owner_id) REFERENCES github_provider_manifest_revisions(tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest, github_repository_owner_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_registry_revisions
    ADD CONSTRAINT github_schedule_registry_revisions_repository_contents_authority FOREIGN KEY (repository_contents_authority_id) REFERENCES github_server_service_authorities(id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_registry_seals
    ADD CONSTRAINT github_schedule_registry_seals_revision FOREIGN KEY (registry_id) REFERENCES github_schedule_registry_revisions(registry_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_runtime
    ADD CONSTRAINT github_schedule_runtime_current FOREIGN KEY (tenant_id, repository_id, provider_connection_id, registry_id) REFERENCES github_schedule_registry_current(tenant_id, repository_id, provider_connection_id, registry_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_runtime
    ADD CONSTRAINT github_schedule_runtime_entry FOREIGN KEY (registry_id, entry_ordinal) REFERENCES github_schedule_registry_entries(registry_id, ordinal) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_entry FOREIGN KEY (registry_id, entry_ordinal) REFERENCES github_schedule_registry_entries(registry_id, ordinal) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_fire FOREIGN KEY (tenant_id, repository_id, provider_connection_id, schedule_fire_id, registry_id, entry_ordinal, scheduled_at_ms) REFERENCES github_schedule_fires(tenant_id, repository_id, provider_connection_id, fire_id, registry_id, entry_ordinal, scheduled_at_ms) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_manifest FOREIGN KEY (tenant_id, repository_id, provider_connection_id, provider_manifest_revision, provider_manifest_digest) REFERENCES github_provider_manifest_revisions(tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_registry FOREIGN KEY (tenant_id, repository_id, provider_connection_id, registry_id, provider_manifest_revision, provider_manifest_digest, git_ref, source_revision, github_repository_owner_id) REFERENCES github_schedule_registry_revisions(tenant_id, repository_id, provider_connection_id, registry_id, manifest_revision, manifest_digest, default_branch_ref, source_revision, github_repository_owner_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_snapshot FOREIGN KEY (snapshot_id, workflow_id) REFERENCES workflow_snapshots(id, workflow_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_schedule_workflow_run_evidence
    ADD CONSTRAINT github_schedule_workflow_run_evidence_workflow FOREIGN KEY (repository_id, workflow_id) REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_current_generation_fk FOREIGN KEY (tenant_id, id, current_issuance_generation) REFERENCES github_server_service_authority_issuances(tenant_id, authority_id, generation) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_refresh_generation_fk FOREIGN KEY (tenant_id, id, refresh_issuance_generation) REFERENCES github_server_service_authority_issuances(tenant_id, authority_id, generation) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_repository_tenant FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_server_service_authority_handoffs
    ADD CONSTRAINT github_server_service_handoffs_issuance_fk FOREIGN KEY (tenant_id, authority_id, generation) REFERENCES github_server_service_authority_issuances(tenant_id, authority_id, generation) ON DELETE RESTRICT;

ALTER TABLE ONLY github_server_service_authority_issuances
    ADD CONSTRAINT github_server_service_issuances_authority_tenant FOREIGN KEY (tenant_id, authority_id) REFERENCES github_server_service_authorities(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_team_membership_observations
    ADD CONSTRAINT github_team_membership_observations_organization FOREIGN KEY (tenant_id, snapshot_id, organization_id) REFERENCES github_organization_membership_observations(tenant_id, snapshot_id, organization_id) ON DELETE CASCADE;

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_attempt FOREIGN KEY (run_id, source_run_id) REFERENCES workflow_rerun_attempts(run_id, source_run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_check FOREIGN KEY (tenant_id, run_id, github_check_subject_id) REFERENCES workflow_rerun_check_evidence(tenant_id, run_id, github_check_subject_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_request FOREIGN KEY (tenant_id, operation_id, run_id) REFERENCES workflow_rerun_requests(tenant_id, operation_id, rerun_run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_snapshot FOREIGN KEY (snapshot_id, workflow_id) REFERENCES workflow_snapshots(id, workflow_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_rerun_subject_evidence
    ADD CONSTRAINT github_workflow_rerun_subject_evidence_workflow FOREIGN KEY (repository_id, workflow_id) REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_check FOREIGN KEY (tenant_id, github_check_subject_id) REFERENCES github_check_subjects(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_delivery FOREIGN KEY (tenant_id, repository_id, provider_delivery_id) REFERENCES github_provider_delivery_evidence(tenant_id, repository_id, provider_delivery_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_repository_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_snapshot FOREIGN KEY (snapshot_id, workflow_id) REFERENCES workflow_snapshots(id, workflow_id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_tenant_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_workflow FOREIGN KEY (repository_id, workflow_id) REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY delegated_actor_identities
    ADD CONSTRAINT delegated_actor_identities_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES human_principals(id) ON DELETE RESTRICT;

ALTER TABLE ONLY human_auth_installation_state
    ADD CONSTRAINT human_auth_installation_state_identity FOREIGN KEY (configured_principal_id, expected_provider_id, expected_provider_subject) REFERENCES human_provider_identities(principal_id, provider_id, provider_subject) ON DELETE RESTRICT;

ALTER TABLE ONLY human_auth_installation_state
    ADD CONSTRAINT human_auth_installation_state_membership FOREIGN KEY (configured_tenant_id, configured_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY human_auth_installation_state
    ADD CONSTRAINT human_auth_installation_state_setup_transaction FOREIGN KEY (setup_transaction_id) REFERENCES human_login_transactions(id) ON DELETE RESTRICT;

ALTER TABLE ONLY human_login_transactions
    ADD CONSTRAINT human_login_transactions_completed_membership FOREIGN KEY (tenant_id, completed_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY human_login_transactions
    ADD CONSTRAINT human_login_transactions_completed_principal FOREIGN KEY (completed_principal_id) REFERENCES human_principals(id) ON DELETE RESTRICT;

ALTER TABLE ONLY human_login_transactions
    ADD CONSTRAINT human_login_transactions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY human_provider_identities
    ADD CONSTRAINT human_provider_identities_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES human_principals(id) ON DELETE RESTRICT;

ALTER TABLE ONLY human_provider_tokens
    ADD CONSTRAINT human_provider_tokens_identity FOREIGN KEY (principal_id, provider_id, provider_subject) REFERENCES human_provider_identities(principal_id, provider_id, provider_subject) ON DELETE RESTRICT;

ALTER TABLE ONLY human_provider_tokens
    ADD CONSTRAINT human_provider_tokens_membership FOREIGN KEY (tenant_id, principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY human_sessions
    ADD CONSTRAINT human_sessions_identity FOREIGN KEY (principal_id, provider_id, provider_subject) REFERENCES human_provider_identities(principal_id, provider_id, provider_subject) ON DELETE RESTRICT;

ALTER TABLE ONLY human_sessions
    ADD CONSTRAINT human_sessions_membership FOREIGN KEY (tenant_id, principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY human_sessions
    ADD CONSTRAINT human_sessions_predecessor FOREIGN KEY (tenant_id, predecessor_session_id) REFERENCES human_sessions(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY job_attempts
    ADD CONSTRAINT job_attempts_job_id_fkey FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE;

ALTER TABLE ONLY job_attempts
    ADD CONSTRAINT job_attempts_runner_id_fkey FOREIGN KEY (runner_id) REFERENCES runners(id) ON DELETE RESTRICT;

ALTER TABLE ONLY job_attempts
    ADD CONSTRAINT job_attempts_session_fence FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY job_dependencies
    ADD CONSTRAINT job_dependencies_job_same_run FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY job_dependencies
    ADD CONSTRAINT job_dependencies_prerequisite_same_run FOREIGN KEY (run_id, prerequisite_job_id) REFERENCES jobs(run_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY job_dependencies
    ADD CONSTRAINT job_dependencies_run_id_fkey FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE;

ALTER TABLE ONLY job_environment_gates
    ADD CONSTRAINT job_environment_gates_approval FOREIGN KEY (tenant_id, repository_id, environment_id, run_id, job_id, attempt_id, approval_request_id) REFERENCES protected_environment_approval_requests(tenant_id, repository_id, environment_id, run_id, job_id, attempt_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY job_environment_gates
    ADD CONSTRAINT job_environment_gates_attempt FOREIGN KEY (job_id, attempt_id) REFERENCES job_attempts(job_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY job_environment_gates
    ADD CONSTRAINT job_environment_gates_environment FOREIGN KEY (tenant_id, repository_id, environment_id) REFERENCES repository_environments(tenant_id, repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY job_environment_gates
    ADD CONSTRAINT job_environment_gates_instance FOREIGN KEY (instance_id) REFERENCES logical_workflow_concrete_jobs(instance_id) ON DELETE CASCADE;

ALTER TABLE ONLY job_environment_gates
    ADD CONSTRAINT job_environment_gates_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY job_environment_gates
    ADD CONSTRAINT job_environment_gates_repository_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY job_environment_gates
    ADD CONSTRAINT job_environment_gates_run_job FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY job_missing_secret_bindings
    ADD CONSTRAINT job_missing_secret_bindings_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES job_environment_gates(attempt_id) ON DELETE CASCADE;

ALTER TABLE ONLY job_missing_variable_bindings
    ADD CONSTRAINT job_missing_variable_bindings_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES job_environment_gates(attempt_id) ON DELETE CASCADE;

ALTER TABLE ONLY job_secret_bindings
    ADD CONSTRAINT job_secret_bindings_grant FOREIGN KEY (tenant_id, grant_id) REFERENCES secret_workload_grants(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY job_secret_bindings
    ADD CONSTRAINT job_secret_bindings_selection FOREIGN KEY (attempt_id, canonical_name) REFERENCES job_secret_selections(attempt_id, canonical_name) ON DELETE CASCADE;

ALTER TABLE ONLY job_secret_selections
    ADD CONSTRAINT job_secret_selections_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES job_environment_gates(attempt_id) ON DELETE CASCADE;

ALTER TABLE ONLY job_secret_selections
    ADD CONSTRAINT job_secret_selections_version FOREIGN KEY (tenant_id, secret_version_id, secret_id, secret_version_number) REFERENCES secret_versions(tenant_id, id, secret_id, version_number) ON DELETE RESTRICT;

ALTER TABLE ONLY job_variable_bindings
    ADD CONSTRAINT job_variable_bindings_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES job_environment_gates(attempt_id) ON DELETE CASCADE;

ALTER TABLE ONLY job_variable_bindings
    ADD CONSTRAINT job_variable_bindings_version FOREIGN KEY (tenant_id, variable_version_id, variable_id, variable_version_number) REFERENCES workflow_variable_versions(tenant_id, id, variable_id, version_number) ON DELETE RESTRICT;

ALTER TABLE ONLY jobs
    ADD CONSTRAINT jobs_run_id_fkey FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE;

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_job_attempt FOREIGN KEY (job_id, attempt_id) REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_repository_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_run_job FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_runner FOREIGN KEY (runner_id) REFERENCES runners(id) ON DELETE RESTRICT;

ALTER TABLE ONLY managed_secret_delivery_operations
    ADD CONSTRAINT managed_secret_delivery_operations_session FOREIGN KEY (runner_session_id) REFERENCES runner_sessions(id) ON DELETE RESTRICT;

ALTER TABLE ONLY protected_environment_approval_decisions
    ADD CONSTRAINT protected_environment_approval_decisions_principal_membership FOREIGN KEY (tenant_id, principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY protected_environment_approval_decisions
    ADD CONSTRAINT protected_environment_approval_decisions_request FOREIGN KEY (tenant_id, request_id) REFERENCES protected_environment_approval_requests(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_requests_environment FOREIGN KEY (tenant_id, repository_id, environment_id) REFERENCES repository_environments(tenant_id, repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_requests_job_attempt FOREIGN KEY (job_id, attempt_id) REFERENCES job_attempts(job_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_requests_repository_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_requests_requester_membership FOREIGN KEY (tenant_id, requested_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_requests_run_job FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY provider_delivery_inbox
    ADD CONSTRAINT provider_delivery_inbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY provider_delivery_workflow_inventories
    ADD CONSTRAINT provider_delivery_workflow_inventories_inbox FOREIGN KEY (inbox_id, tenant_id) REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT;

ALTER TABLE ONLY provider_delivery_workflow_inventory_entries
    ADD CONSTRAINT provider_delivery_workflow_inventory_entries_inventory FOREIGN KEY (tenant_id, inbox_id) REFERENCES provider_delivery_workflow_inventories(tenant_id, inbox_id) ON DELETE RESTRICT;

ALTER TABLE ONLY provider_delivery_workflow_outcomes
    ADD CONSTRAINT provider_delivery_workflow_outcomes_inbox_tenant FOREIGN KEY (inbox_id, tenant_id) REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT;

ALTER TABLE ONLY provider_delivery_workflow_outcomes
    ADD CONSTRAINT provider_delivery_workflow_outcomes_repository_tenant FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY provider_delivery_workflow_outcomes
    ADD CONSTRAINT provider_delivery_workflow_outcomes_run_repository FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY provider_delivery_workflow_progress
    ADD CONSTRAINT provider_delivery_workflow_progress_admitted_run_exact FOREIGN KEY (inbox_id, workflow_path, run_id) REFERENCES github_workflow_run_subject_evidence(provider_delivery_id, workflow_path, run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY provider_delivery_workflow_progress
    ADD CONSTRAINT provider_delivery_workflow_progress_entry FOREIGN KEY (inbox_id, workflow_path) REFERENCES provider_delivery_workflow_inventory_entries(inbox_id, workflow_path) ON DELETE RESTRICT;

ALTER TABLE ONLY provider_delivery_workflow_progress
    ADD CONSTRAINT provider_delivery_workflow_progress_inventory FOREIGN KEY (tenant_id, inbox_id, inventory_digest) REFERENCES provider_delivery_workflow_inventories(tenant_id, inbox_id, inventory_digest) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_role_bindings
    ADD CONSTRAINT rbac_role_bindings_creator_membership FOREIGN KEY (tenant_id, created_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_role_bindings
    ADD CONSTRAINT rbac_role_bindings_principal_membership FOREIGN KEY (tenant_id, principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_role_bindings
    ADD CONSTRAINT rbac_role_bindings_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_role_bindings
    ADD CONSTRAINT rbac_role_bindings_revoker_membership FOREIGN KEY (tenant_id, revoked_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_role_bindings
    ADD CONSTRAINT rbac_role_bindings_role FOREIGN KEY (tenant_id, role_id) REFERENCES rbac_roles(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_role_bindings
    ADD CONSTRAINT rbac_role_bindings_runner_group FOREIGN KEY (tenant_id, runner_group_id) REFERENCES runner_groups(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_role_permissions
    ADD CONSTRAINT rbac_role_permissions_grantor_membership FOREIGN KEY (tenant_id, granted_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_role_permissions
    ADD CONSTRAINT rbac_role_permissions_permission_name_fkey FOREIGN KEY (permission_name) REFERENCES rbac_permissions(name) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_role_permissions
    ADD CONSTRAINT rbac_role_permissions_role FOREIGN KEY (tenant_id, role_id) REFERENCES rbac_roles(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY rbac_roles
    ADD CONSTRAINT rbac_roles_creator_membership FOREIGN KEY (tenant_id, created_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY rbac_roles
    ADD CONSTRAINT rbac_roles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY repositories
    ADD CONSTRAINT repositories_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY repository_environment_reviewers
    ADD CONSTRAINT repository_environment_reviewers_environment FOREIGN KEY (tenant_id, repository_id, environment_id) REFERENCES repository_environments(tenant_id, repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY repository_environment_reviewers
    ADD CONSTRAINT repository_environment_reviewers_grantor FOREIGN KEY (tenant_id, granted_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY repository_environment_reviewers
    ADD CONSTRAINT repository_environment_reviewers_principal FOREIGN KEY (tenant_id, principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY repository_environments
    ADD CONSTRAINT repository_environments_creator_membership FOREIGN KEY (tenant_id, created_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY repository_environments
    ADD CONSTRAINT repository_environments_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY repository_publication_policies
    ADD CONSTRAINT repository_publication_policies_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY repository_publication_policies
    ADD CONSTRAINT repository_publication_policies_updater_membership FOREIGN KEY (tenant_id, updated_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_command_outbox
    ADD CONSTRAINT runner_command_outbox_session_fence FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_command_outbox
    ADD CONSTRAINT runner_command_outbox_tenant_runner FOREIGN KEY (tenant_id, runner_id) REFERENCES runners(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_groups
    ADD CONSTRAINT runner_groups_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_lease_offer_publications
    ADD CONSTRAINT runner_lease_offer_publications_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES job_attempts(id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_lease_offer_publications
    ADD CONSTRAINT runner_lease_offer_publications_command FOREIGN KEY (runner_session_id, command_sequence) REFERENCES runner_command_outbox(runner_session_id, command_sequence) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_lease_offer_publications
    ADD CONSTRAINT runner_lease_offer_publications_job_id_fkey FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_lease_offer_publications
    ADD CONSTRAINT runner_lease_offer_publications_run_id_fkey FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_lease_offer_publications
    ADD CONSTRAINT runner_lease_offer_publications_session_fence FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_lease_request_heads
    ADD CONSTRAINT runner_lease_request_heads_session_fence FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_machine_certificates
    ADD CONSTRAINT runner_machine_certificates_runner_id_fkey FOREIGN KEY (runner_id) REFERENCES runners(id) ON DELETE CASCADE;

ALTER TABLE ONLY runner_enrollment_tokens
    ADD CONSTRAINT runner_enrollment_tokens_group_fkey FOREIGN KEY (tenant_id, runner_group_id) REFERENCES runner_groups(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_enrollment_tokens
    ADD CONSTRAINT runner_enrollment_tokens_issuer_membership_fkey FOREIGN KEY (tenant_id, issued_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_enrollment_tokens
    ADD CONSTRAINT runner_enrollment_tokens_issuer_session_fkey FOREIGN KEY (tenant_id, issued_by_principal_id, issued_by_session_id) REFERENCES human_sessions(tenant_id, principal_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_enrollment_tokens
    ADD CONSTRAINT runner_enrollment_tokens_consumed_runner_fkey FOREIGN KEY (tenant_id, consumed_runner_id) REFERENCES runners(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_enrollment_tokens
    ADD CONSTRAINT runner_enrollment_tokens_tenant_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_operation_receipts
    ADD CONSTRAINT runner_operation_receipts_session_fence FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_queue_cursors
    ADD CONSTRAINT runner_queue_cursors_runner_id_fkey FOREIGN KEY (runner_id) REFERENCES runners(id) ON DELETE CASCADE;

ALTER TABLE ONLY runner_rpc_receipts
    ADD CONSTRAINT runner_rpc_receipts_lease_offer_publication FOREIGN KEY (runner_session_id, lease_offer_request_operation_id, lease_offer_command_sequence) REFERENCES runner_lease_offer_publications(runner_session_id, request_operation_id, command_sequence) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_rpc_receipts
    ADD CONSTRAINT runner_rpc_receipts_session_fence FOREIGN KEY (runner_id, runner_session_id, runner_session_epoch, runner_generation) REFERENCES runner_sessions(runner_id, id, session_epoch, runner_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_rpc_receipts
    ADD CONSTRAINT runner_rpc_receipts_tenant_runner FOREIGN KEY (tenant_id, runner_id) REFERENCES runners(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY runner_sessions
    ADD CONSTRAINT runner_sessions_runner_id_fkey FOREIGN KEY (runner_id) REFERENCES runners(id) ON DELETE CASCADE;

ALTER TABLE ONLY runners
    ADD CONSTRAINT runners_group_matches_tenant FOREIGN KEY (tenant_id, group_id) REFERENCES runner_groups(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY runners
    ADD CONSTRAINT runners_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_cleanup_outbox
    ADD CONSTRAINT secret_cleanup_outbox_provider FOREIGN KEY (tenant_id, provider_id) REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_cleanup_outbox
    ADD CONSTRAINT secret_cleanup_outbox_provider_lease FOREIGN KEY (tenant_id, provider_lease_record_id) REFERENCES secret_provider_leases(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY secret_cleanup_outbox
    ADD CONSTRAINT secret_cleanup_outbox_secret_version FOREIGN KEY (tenant_id, secret_version_id, secret_id, version_number) REFERENCES secret_versions(tenant_id, id, secret_id, version_number) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_cleanup_outbox
    ADD CONSTRAINT secret_cleanup_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_key_rotation_items
    ADD CONSTRAINT secret_key_rotation_items_rotation FOREIGN KEY (tenant_id, rotation_id) REFERENCES secret_key_rotations(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY secret_key_rotation_items
    ADD CONSTRAINT secret_key_rotation_items_version FOREIGN KEY (tenant_id, secret_version_id, secret_id, version_number) REFERENCES secret_versions(tenant_id, id, secret_id, version_number) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_key_rotations
    ADD CONSTRAINT secret_key_rotations_initiator_membership FOREIGN KEY (tenant_id, initiated_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_key_rotations
    ADD CONSTRAINT secret_key_rotations_provider FOREIGN KEY (tenant_id, provider_id) REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_mutation_recovery_outbox
    ADD CONSTRAINT secret_mutation_recovery_outbox_mutation FOREIGN KEY (tenant_id, mutation_id) REFERENCES secret_version_mutations(tenant_id, mutation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_mutation_recovery_outbox
    ADD CONSTRAINT secret_mutation_recovery_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_policies
    ADD CONSTRAINT secret_policies_secret_scope FOREIGN KEY (tenant_id, secret_id, secret_scope_kind) REFERENCES secrets(tenant_id, id, scope_kind) ON DELETE CASCADE;

ALTER TABLE ONLY secret_policies
    ADD CONSTRAINT secret_policies_updater_membership FOREIGN KEY (tenant_id, updated_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_provider_configuration_envelope_heads
    ADD CONSTRAINT secret_provider_configuration_envelope_heads_envelope FOREIGN KEY (tenant_id, provider_id, envelope_generation) REFERENCES secret_provider_configuration_envelopes(tenant_id, provider_id, envelope_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_provider_configuration_envelopes
    ADD CONSTRAINT secret_provider_configuration_envelopes_provider FOREIGN KEY (tenant_id, provider_id) REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_provider_lease_envelope_heads
    ADD CONSTRAINT secret_provider_lease_envelope_heads_envelope FOREIGN KEY (tenant_id, provider_lease_record_id, envelope_generation) REFERENCES secret_provider_lease_envelopes(tenant_id, provider_lease_record_id, envelope_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_provider_lease_envelopes
    ADD CONSTRAINT secret_provider_lease_envelopes_lease FOREIGN KEY (tenant_id, provider_lease_record_id, provider_id) REFERENCES secret_provider_leases(tenant_id, id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_provider_leases
    ADD CONSTRAINT secret_provider_leases_provider FOREIGN KEY (tenant_id, provider_id) REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_provider_leases
    ADD CONSTRAINT secret_provider_leases_workload_grant FOREIGN KEY (tenant_id, workload_grant_id) REFERENCES secret_workload_grants(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY secret_provider_locator_envelope_heads
    ADD CONSTRAINT secret_provider_locator_envelope_heads_envelope FOREIGN KEY (tenant_id, secret_id, envelope_generation) REFERENCES secret_provider_locator_envelopes(tenant_id, secret_id, envelope_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_provider_locator_envelopes
    ADD CONSTRAINT secret_provider_locator_envelopes_secret FOREIGN KEY (tenant_id, secret_id, provider_id) REFERENCES secrets(tenant_id, id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_provider_version_envelope_heads
    ADD CONSTRAINT secret_provider_version_envelope_heads_envelope FOREIGN KEY (tenant_id, secret_version_id, envelope_generation) REFERENCES secret_provider_version_envelopes(tenant_id, secret_version_id, envelope_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_provider_version_envelopes
    ADD CONSTRAINT secret_provider_version_envelopes_version FOREIGN KEY (tenant_id, secret_version_id, secret_id, version_number, provider_id) REFERENCES secret_versions(tenant_id, id, secret_id, version_number, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_providers
    ADD CONSTRAINT secret_providers_creator_membership FOREIGN KEY (tenant_id, created_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_providers
    ADD CONSTRAINT secret_providers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_repository_access
    ADD CONSTRAINT secret_repository_access_grantor_membership FOREIGN KEY (tenant_id, granted_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_repository_access
    ADD CONSTRAINT secret_repository_access_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY secret_repository_access
    ADD CONSTRAINT secret_repository_access_secret_scope FOREIGN KEY (tenant_id, secret_id, secret_scope_kind) REFERENCES secrets(tenant_id, id, scope_kind) ON DELETE CASCADE;

ALTER TABLE ONLY secret_version_envelope_heads
    ADD CONSTRAINT secret_version_envelope_heads_envelope FOREIGN KEY (tenant_id, secret_version_id, envelope_generation) REFERENCES secret_version_envelopes(tenant_id, secret_version_id, envelope_generation) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_envelopes
    ADD CONSTRAINT secret_version_envelopes_builtin_version FOREIGN KEY (tenant_id, secret_version_id, secret_id, version_number, storage_kind) REFERENCES secret_versions(tenant_id, id, secret_id, version_number, storage_kind) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_envelopes
    ADD CONSTRAINT secret_version_envelopes_custody_canary FOREIGN KEY (wrapping_key_id) REFERENCES secret_custody_key_canaries(wrapping_key_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_lifecycle
    ADD CONSTRAINT secret_version_lifecycle_changer_membership FOREIGN KEY (tenant_id, changed_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_lifecycle
    ADD CONSTRAINT secret_version_lifecycle_mutation FOREIGN KEY (tenant_id, mutation_id, secret_id, provider_id) REFERENCES secret_version_mutations(tenant_id, mutation_id, secret_id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_lifecycle
    ADD CONSTRAINT secret_version_lifecycle_version FOREIGN KEY (tenant_id, secret_version_id, secret_id, version_number, provider_id) REFERENCES secret_versions(tenant_id, id, secret_id, version_number, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_abandoned_version FOREIGN KEY (tenant_id, abandoned_version_id, secret_id, abandoned_version_number) REFERENCES secret_versions(tenant_id, id, secret_id, version_number) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_committed_version FOREIGN KEY (tenant_id, committed_version_id, secret_id, committed_version_number) REFERENCES secret_versions(tenant_id, id, secret_id, version_number) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_confirmer_membership FOREIGN KEY (tenant_id, confirmed_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_confirmer_session FOREIGN KEY (tenant_id, confirmed_by_principal_id, confirmed_by_session_id) REFERENCES human_sessions(tenant_id, principal_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_environment FOREIGN KEY (tenant_id, repository_id, environment_id) REFERENCES repository_environments(tenant_id, repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_predecessor FOREIGN KEY (tenant_id, expected_predecessor_version_id, secret_id, expected_predecessor_version_number) REFERENCES secret_versions(tenant_id, id, secret_id, version_number) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_provider FOREIGN KEY (tenant_id, provider_id) REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_requested_provider FOREIGN KEY (tenant_id, requested_provider_id) REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_reserver_membership FOREIGN KEY (tenant_id, reserved_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_reserver_session FOREIGN KEY (tenant_id, reserved_by_principal_id, reserved_by_session_id) REFERENCES human_sessions(tenant_id, principal_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_versions
    ADD CONSTRAINT secret_versions_creator_membership FOREIGN KEY (tenant_id, created_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_versions
    ADD CONSTRAINT secret_versions_secret_provider FOREIGN KEY (tenant_id, secret_id, provider_id) REFERENCES secrets(tenant_id, id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_environment FOREIGN KEY (tenant_id, repository_id, environment_id) REFERENCES repository_environments(tenant_id, repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_environment_approval FOREIGN KEY (tenant_id, repository_id, environment_id, run_id, job_id, attempt_id, environment_approval_request_id) REFERENCES protected_environment_approval_requests(tenant_id, repository_id, environment_id, run_id, job_id, attempt_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_job_attempt FOREIGN KEY (job_id, attempt_id) REFERENCES job_attempts(job_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_repository_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_run_job FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY secret_workload_grants
    ADD CONSTRAINT secret_workload_grants_secret_version FOREIGN KEY (tenant_id, secret_version_id, secret_id, secret_version_number, provider_id) REFERENCES secret_versions(tenant_id, id, secret_id, version_number, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_creator_membership FOREIGN KEY (tenant_id, created_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_current_version FOREIGN KEY (tenant_id, current_version_id, id, current_version_number) REFERENCES secret_versions(tenant_id, id, secret_id, version_number) ON DELETE RESTRICT;

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_environment FOREIGN KEY (tenant_id, repository_id, environment_id) REFERENCES repository_environments(tenant_id, repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_provider FOREIGN KEY (tenant_id, provider_id) REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT;

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_updater_membership FOREIGN KEY (tenant_id, updated_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY security_audit_events
    ADD CONSTRAINT security_audit_events_actor_membership FOREIGN KEY (tenant_id, actor_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY security_audit_events
    ADD CONSTRAINT security_audit_events_actor_session FOREIGN KEY (tenant_id, actor_principal_id, actor_session_id) REFERENCES human_sessions(tenant_id, principal_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY security_audit_events
    ADD CONSTRAINT security_audit_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY tenant_human_memberships
    ADD CONSTRAINT tenant_human_memberships_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES human_principals(id) ON DELETE RESTRICT;

ALTER TABLE ONLY tenant_human_memberships
    ADD CONSTRAINT tenant_human_memberships_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workspace_provisioning_operations
    ADD CONSTRAINT workspace_provisioning_operations_identity FOREIGN KEY (initial_owner_issuer, initial_owner_subject, initial_owner_principal_id) REFERENCES delegated_actor_identities(issuer, subject, principal_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY workspace_provisioning_operations
    ADD CONSTRAINT workspace_provisioning_operations_workspace FOREIGN KEY (workspace_id) REFERENCES tenants(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY workspace_management_bindings
    ADD CONSTRAINT workspace_management_bindings_workspace FOREIGN KEY (workspace_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_admission_receipts
    ADD CONSTRAINT workflow_admission_receipts_repository_tenant FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_admission_receipts
    ADD CONSTRAINT workflow_admission_receipts_run_repository FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_admission_receipts
    ADD CONSTRAINT workflow_admission_receipts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_artifact_block_commits
    ADD CONSTRAINT workflow_artifact_block_commits_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES workflow_artifacts(id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_artifact_blocks
    ADD CONSTRAINT workflow_artifact_blocks_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES workflow_artifacts(id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_artifacts
    ADD CONSTRAINT workflow_artifacts_job_attempt FOREIGN KEY (job_id, attempt_id) REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_artifacts
    ADD CONSTRAINT workflow_artifacts_repository_run FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_artifacts
    ADD CONSTRAINT workflow_artifacts_run_job FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_artifacts
    ADD CONSTRAINT workflow_artifacts_tenant_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_definitions
    ADD CONSTRAINT workflow_definitions_repository_id_fkey FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_activation_preparation_claims
    ADD CONSTRAINT logical_workflow_activation_preparation_claims_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_activation_preparation_outputs
    ADD CONSTRAINT logical_workflow_activation_preparation_outputs_prerequisite_fk FOREIGN KEY (logical_job_id, prerequisite_job_id) REFERENCES logical_workflow_activation_preparation_prerequisites(logical_job_id, prerequisite_job_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_activation_preparation_prerequisites
    ADD CONSTRAINT logical_workflow_activation_preparation_pre_logical_job_id_fkey FOREIGN KEY (logical_job_id) REFERENCES logical_workflow_activation_preparation_claims(logical_job_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_activation_preparations
    ADD CONSTRAINT logical_workflow_activation_preparations_claim_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_activation_preparation_claims(run_id, invocation_id, logical_job_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_activation_publications
    ADD CONSTRAINT logical_workflow_activation_publications_job_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_activation_work_quarantines
    ADD CONSTRAINT logical_workflow_activation_quarantine_selection_fk FOREIGN KEY (selection_id) REFERENCES logical_workflow_activation_work_selections(selection_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_activation_work_quarantines
    ADD CONSTRAINT logical_workflow_activation_quarantine_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_activation_renewal_receipts
    ADD CONSTRAINT logical_workflow_activation_renewal_selection_fk FOREIGN KEY (selection_id) REFERENCES logical_workflow_activation_work_selections(selection_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_activation_renewal_receipts
    ADD CONSTRAINT logical_workflow_activation_renewal_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_concrete_jobs
    ADD CONSTRAINT logical_workflow_concrete_jobs_claim_fk FOREIGN KEY (run_id, invocation_id, logical_job_id, instance_id) REFERENCES logical_workflow_materialization_claims(run_id, invocation_id, logical_job_id, instance_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_concrete_jobs
    ADD CONSTRAINT logical_workflow_concrete_jobs_initial_attempt_id_fkey FOREIGN KEY (initial_attempt_id) REFERENCES job_attempts(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY logical_workflow_concrete_jobs
    ADD CONSTRAINT logical_workflow_concrete_jobs_job_id_fkey FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY logical_workflow_concurrency_cancellations
    ADD CONSTRAINT logical_workflow_concurrency_cancellatio_preempting_run_id_fkey FOREIGN KEY (preempting_run_id) REFERENCES workflow_runs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_concurrency_cancellations
    ADD CONSTRAINT logical_workflow_concurrency_cancellations_invocation_fk FOREIGN KEY (run_id, root_invocation_id) REFERENCES logical_workflow_invocations(run_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_concurrency_cancellations
    ADD CONSTRAINT logical_workflow_concurrency_cancellations_run_id_fkey FOREIGN KEY (run_id) REFERENCES logical_workflow_runs(run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_dependencies
    ADD CONSTRAINT logical_workflow_dependencies_job_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_dependencies
    ADD CONSTRAINT logical_workflow_dependencies_prerequisite_fk FOREIGN KEY (run_id, invocation_id, prerequisite_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_instance_result_claims
    ADD CONSTRAINT logical_workflow_instance_result_claims_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES attempt_terminal_results(attempt_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_instance_result_claims
    ADD CONSTRAINT logical_workflow_instance_result_claims_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES logical_workflow_concrete_jobs(instance_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_instance_result_due
    ADD CONSTRAINT logical_workflow_instance_result_due_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES attempt_terminal_results(attempt_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_instance_result_outputs
    ADD CONSTRAINT logical_workflow_instance_result_outputs_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES logical_workflow_instance_results(instance_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_instance_result_quarantines
    ADD CONSTRAINT logical_workflow_instance_result_quarantines_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES attempt_terminal_results(attempt_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_instance_result_quarantines
    ADD CONSTRAINT logical_workflow_instance_result_quarantines_job_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_instance_result_selections
    ADD CONSTRAINT logical_workflow_instance_result_selections_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES attempt_terminal_results(attempt_id);

ALTER TABLE ONLY logical_workflow_instance_results
    ADD CONSTRAINT logical_workflow_instance_results_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES logical_workflow_instance_result_claims(attempt_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_instance_results
    ADD CONSTRAINT logical_workflow_instance_results_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES logical_workflow_instance_result_claims(instance_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_instance_results
    ADD CONSTRAINT logical_workflow_instance_results_server_intent_fk FOREIGN KEY (attempt_id, server_cancellation_operation_id) REFERENCES attempt_cancellation_intents(attempt_id, operation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_instances
    ADD CONSTRAINT logical_workflow_instances_publication_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_activation_publications(run_id, invocation_id, logical_job_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_invocations
    ADD CONSTRAINT logical_workflow_invocations_run_id_fkey FOREIGN KEY (run_id) REFERENCES logical_workflow_runs(run_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_job_environment_evidence
    ADD CONSTRAINT logical_workflow_job_environment_evidence_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES logical_workflow_instances(id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_job_result_claims
    ADD CONSTRAINT logical_workflow_job_result_claims_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_job_result_due
    ADD CONSTRAINT logical_workflow_job_result_due_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_job_result_instances
    ADD CONSTRAINT logical_workflow_job_result_instances_logical_job_id_fkey FOREIGN KEY (logical_job_id) REFERENCES logical_workflow_job_results(logical_job_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_job_result_outputs
    ADD CONSTRAINT logical_workflow_job_result_outputs_logical_job_id_fkey FOREIGN KEY (logical_job_id) REFERENCES logical_workflow_job_results(logical_job_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_job_result_prerequisites
    ADD CONSTRAINT logical_workflow_job_result_prerequisites_logical_job_id_fkey FOREIGN KEY (logical_job_id) REFERENCES logical_workflow_job_results(logical_job_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_job_result_quarantines
    ADD CONSTRAINT logical_workflow_job_result_quarantines_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_job_result_selections
    ADD CONSTRAINT logical_workflow_job_result_selections_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) MATCH FULL;

ALTER TABLE ONLY logical_workflow_job_results
    ADD CONSTRAINT logical_workflow_job_results_logical_job_id_fkey FOREIGN KEY (logical_job_id) REFERENCES logical_workflow_job_result_claims(logical_job_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_job_results
    ADD CONSTRAINT logical_workflow_job_results_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_job_result_claims(run_id, invocation_id, logical_job_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_job_terminal_counters
    ADD CONSTRAINT logical_workflow_job_terminal_counters_logical_job_id_fkey FOREIGN KEY (logical_job_id) REFERENCES logical_workflow_jobs(id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_jobs
    ADD CONSTRAINT logical_workflow_jobs_invocation_fk FOREIGN KEY (run_id, invocation_id) REFERENCES logical_workflow_invocations(run_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_materialization_claims
    ADD CONSTRAINT logical_workflow_materialization_claims_instance_fk FOREIGN KEY (run_id, invocation_id, logical_job_id, instance_id) REFERENCES logical_workflow_instances(run_id, invocation_id, logical_job_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_materialization_work_quarantines
    ADD CONSTRAINT logical_workflow_materialization_quarantine_selection_fk FOREIGN KEY (selection_id) REFERENCES logical_workflow_materialization_work_selections(selection_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_materialization_work_quarantines
    ADD CONSTRAINT logical_workflow_materialization_quarantine_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id, instance_id) REFERENCES logical_workflow_instances(run_id, invocation_id, logical_job_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_materialization_renewal_receipts
    ADD CONSTRAINT logical_workflow_materialization_renewal_selection_fk FOREIGN KEY (selection_id) REFERENCES logical_workflow_materialization_work_selections(selection_id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_materialization_renewal_receipts
    ADD CONSTRAINT logical_workflow_materialization_renewal_target_fk FOREIGN KEY (run_id, invocation_id, logical_job_id, instance_id) REFERENCES logical_workflow_instances(run_id, invocation_id, logical_job_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_output_contracts
    ADD CONSTRAINT logical_workflow_reusable_call_output_contracts_expansion_fk FOREIGN KEY (run_id, child_invocation_id) REFERENCES logical_workflow_reusable_invocation_expansions(run_id, invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_output_mappings
    ADD CONSTRAINT logical_workflow_reusable_call_output_mappings_child_fk FOREIGN KEY (run_id, child_invocation_id) REFERENCES logical_workflow_reusable_call_output_contracts(run_id, child_invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_output_mappings
    ADD CONSTRAINT logical_workflow_reusable_call_output_mappings_output_fk FOREIGN KEY (run_id, child_invocation_id, child_output_name) REFERENCES logical_workflow_reusable_outputs(run_id, invocation_id, output_key) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_publications
    ADD CONSTRAINT logical_workflow_reusable_call_publications_outputs_fk FOREIGN KEY (run_id, child_invocation_id) REFERENCES logical_workflow_reusable_call_output_contracts(run_id, child_invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_publications
    ADD CONSTRAINT logical_workflow_reusable_call_publications_parent_job_fk FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_publications
    ADD CONSTRAINT logical_workflow_reusable_call_publications_plan_fk FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id, child_invocation_id) REFERENCES logical_workflow_reusable_invocation_expansions(run_id, parent_invocation_id, caller_logical_job_id, invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_publications
    ADD CONSTRAINT logical_workflow_reusable_call_publications_repository_fk FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_publications
    ADD CONSTRAINT logical_workflow_reusable_call_publications_run_fk FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_result_jobs
    ADD CONSTRAINT logical_workflow_reusable_call_result_jobs_result_fk FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id) REFERENCES logical_workflow_reusable_call_results(run_id, parent_invocation_id, caller_logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_result_outputs
    ADD CONSTRAINT logical_workflow_reusable_call_result_outputs_result_fk FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id) REFERENCES logical_workflow_reusable_call_results(run_id, parent_invocation_id, caller_logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_results
    ADD CONSTRAINT logical_workflow_reusable_call_results_publication_fk FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id) REFERENCES logical_workflow_reusable_call_publications(run_id, parent_invocation_id, caller_logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_results
    ADD CONSTRAINT logical_workflow_reusable_call_results_repository_fk FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_call_results
    ADD CONSTRAINT logical_workflow_reusable_call_results_run_fk FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_workflow_catalog
    ADD CONSTRAINT logical_workflow_reusable_catalog_run_fk FOREIGN KEY (run_id) REFERENCES logical_workflow_reusable_workflow_runs(run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_expanded_dependencies
    ADD CONSTRAINT logical_workflow_reusable_expanded_dependencies_job_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_reusable_expanded_jobs(run_id, invocation_id, logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_expanded_dependencies
    ADD CONSTRAINT logical_workflow_reusable_expanded_dependencies_prerequisite_fk FOREIGN KEY (run_id, invocation_id, prerequisite_job_id) REFERENCES logical_workflow_reusable_expanded_jobs(run_id, invocation_id, logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_expanded_jobs
    ADD CONSTRAINT logical_workflow_reusable_expanded_jobs_invocation_fk FOREIGN KEY (run_id, invocation_id) REFERENCES logical_workflow_reusable_invocation_expansions(run_id, invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_invocation_expansions
    ADD CONSTRAINT logical_workflow_reusable_expansions_caller_job_fk FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id) REFERENCES logical_workflow_reusable_expanded_jobs(run_id, invocation_id, logical_job_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY logical_workflow_reusable_invocation_expansions
    ADD CONSTRAINT logical_workflow_reusable_expansions_catalog_exact_fk FOREIGN KEY (run_id, catalog_entry_id, source_digest, plan_digest) REFERENCES logical_workflow_reusable_workflow_catalog(run_id, catalog_entry_id, source_digest, plan_digest) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_invocation_expansions
    ADD CONSTRAINT logical_workflow_reusable_expansions_parent_fk FOREIGN KEY (run_id, parent_invocation_id) REFERENCES logical_workflow_reusable_invocation_expansions(run_id, invocation_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY logical_workflow_reusable_input_bindings
    ADD CONSTRAINT logical_workflow_reusable_input_bindings_invocation_fk FOREIGN KEY (run_id, invocation_id) REFERENCES logical_workflow_reusable_invocation_expansions(run_id, invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_outputs
    ADD CONSTRAINT logical_workflow_reusable_outputs_invocation_fk FOREIGN KEY (run_id, invocation_id) REFERENCES logical_workflow_reusable_invocation_expansions(run_id, invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_permission_grants
    ADD CONSTRAINT logical_workflow_reusable_permission_grants_snapshot_fk FOREIGN KEY (run_id, invocation_id) REFERENCES logical_workflow_reusable_permission_snapshots(run_id, invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_permission_snapshots
    ADD CONSTRAINT logical_workflow_reusable_permission_snapshots_invocation_fk FOREIGN KEY (run_id, invocation_id) REFERENCES logical_workflow_reusable_invocation_expansions(run_id, invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_workflow_runs
    ADD CONSTRAINT logical_workflow_reusable_runs_repository_fk FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_workflow_runs
    ADD CONSTRAINT logical_workflow_reusable_runs_root_fk FOREIGN KEY (run_id, root_invocation_id) REFERENCES logical_workflow_invocations(run_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_workflow_runs
    ADD CONSTRAINT logical_workflow_reusable_runs_run_fk FOREIGN KEY (repository_id, run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_reusable_secret_bindings
    ADD CONSTRAINT logical_workflow_reusable_secret_bindings_invocation_fk FOREIGN KEY (run_id, invocation_id) REFERENCES logical_workflow_reusable_invocation_expansions(run_id, invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_run_result_claims
    ADD CONSTRAINT logical_workflow_run_result_claims_run_id_fkey FOREIGN KEY (run_id) REFERENCES logical_workflow_runs(run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_run_result_claims
    ADD CONSTRAINT logical_workflow_run_result_claims_target_fk FOREIGN KEY (run_id, root_invocation_id) REFERENCES logical_workflow_invocations(run_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_run_result_jobs
    ADD CONSTRAINT logical_workflow_run_result_jobs_logical_job_fk FOREIGN KEY (run_id, root_invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_run_result_jobs
    ADD CONSTRAINT logical_workflow_run_result_jobs_result_fk FOREIGN KEY (run_id, root_invocation_id) REFERENCES logical_workflow_run_results(run_id, root_invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_run_results
    ADD CONSTRAINT logical_workflow_run_results_run_id_fkey FOREIGN KEY (run_id) REFERENCES logical_workflow_run_result_claims(run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_run_results
    ADD CONSTRAINT logical_workflow_run_results_target_fk FOREIGN KEY (run_id, root_invocation_id) REFERENCES logical_workflow_run_result_claims(run_id, root_invocation_id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_runs
    ADD CONSTRAINT logical_workflow_runs_root_invocation FOREIGN KEY (run_id, root_invocation_id) REFERENCES logical_workflow_invocations(run_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY logical_workflow_runs
    ADD CONSTRAINT logical_workflow_runs_run_id_fkey FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE;

ALTER TABLE ONLY logical_workflow_runtime_policy_pins
    ADD CONSTRAINT logical_workflow_runtime_policy_pins_repository_fk FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_runtime_policy_pins
    ADD CONSTRAINT logical_workflow_runtime_policy_pins_revision_fk FOREIGN KEY (tenant_id, repository_id, policy_revision, policy_digest) REFERENCES workflow_runtime_policy_revisions(tenant_id, repository_id, policy_revision, policy_digest) ON DELETE RESTRICT;

ALTER TABLE ONLY logical_workflow_runtime_policy_pins
    ADD CONSTRAINT logical_workflow_runtime_policy_pins_run_fk FOREIGN KEY (run_id) REFERENCES logical_workflow_runs(run_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY workflow_rerun_attempt_jobs
    ADD CONSTRAINT workflow_rerun_attempt_jobs_logical_job_id_fkey FOREIGN KEY (logical_job_id) REFERENCES logical_workflow_jobs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_attempt_jobs
    ADD CONSTRAINT workflow_rerun_attempt_jobs_run_id_fkey FOREIGN KEY (run_id) REFERENCES workflow_rerun_attempts(run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_attempt_jobs
    ADD CONSTRAINT workflow_rerun_attempt_jobs_source_job_fk FOREIGN KEY (source_run_id, source_logical_job_id) REFERENCES logical_workflow_run_result_jobs(run_id, logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_attempt_jobs
    ADD CONSTRAINT workflow_rerun_attempt_jobs_source_logical_job_id_fkey FOREIGN KEY (source_logical_job_id) REFERENCES logical_workflow_jobs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_attempt_jobs
    ADD CONSTRAINT workflow_rerun_attempt_jobs_source_run_fk FOREIGN KEY (run_id, source_run_id) REFERENCES workflow_rerun_attempts(run_id, source_run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_attempt_jobs
    ADD CONSTRAINT workflow_rerun_attempt_jobs_source_run_id_fkey FOREIGN KEY (source_run_id) REFERENCES workflow_runs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_attempts
    ADD CONSTRAINT workflow_rerun_attempts_root_run_id_fkey FOREIGN KEY (root_run_id) REFERENCES workflow_runs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_attempts
    ADD CONSTRAINT workflow_rerun_attempts_run_id_fkey FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_attempts
    ADD CONSTRAINT workflow_rerun_attempts_source_run_id_fkey FOREIGN KEY (source_run_id) REFERENCES workflow_runs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_audit_evidence
    ADD CONSTRAINT workflow_rerun_audit_evidence_event_id_fkey FOREIGN KEY (event_id) REFERENCES security_audit_events(event_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_audit_evidence
    ADD CONSTRAINT workflow_rerun_audit_evidence_request FOREIGN KEY (tenant_id, operation_id, run_id) REFERENCES workflow_rerun_requests(tenant_id, operation_id, rerun_run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_audit_evidence
    ADD CONSTRAINT workflow_rerun_audit_evidence_run_id_fkey FOREIGN KEY (run_id) REFERENCES workflow_rerun_attempts(run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_carried_job_outputs
    ADD CONSTRAINT workflow_rerun_carried_job_outputs_logical_job_id_fkey FOREIGN KEY (logical_job_id) REFERENCES workflow_rerun_carried_job_results(logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_carried_job_results
    ADD CONSTRAINT workflow_rerun_carried_job_results_job_fk FOREIGN KEY (run_id, invocation_id, logical_job_id) REFERENCES logical_workflow_jobs(run_id, invocation_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_carried_job_results
    ADD CONSTRAINT workflow_rerun_carried_job_results_logical_job_id_fkey FOREIGN KEY (logical_job_id) REFERENCES logical_workflow_jobs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_carried_job_results
    ADD CONSTRAINT workflow_rerun_carried_job_results_mapping_fk FOREIGN KEY (run_id, source_run_id, logical_job_id, source_logical_job_id) REFERENCES workflow_rerun_attempt_jobs(run_id, source_run_id, logical_job_id, source_logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_carried_job_results
    ADD CONSTRAINT workflow_rerun_carried_job_results_run_id_fkey FOREIGN KEY (run_id) REFERENCES workflow_rerun_attempts(run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_carried_job_results
    ADD CONSTRAINT workflow_rerun_carried_job_results_source_fk FOREIGN KEY (source_run_id, source_logical_job_id) REFERENCES logical_workflow_run_result_jobs(run_id, logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_carried_job_results
    ADD CONSTRAINT workflow_rerun_carried_job_results_source_run_fk FOREIGN KEY (run_id, source_run_id) REFERENCES workflow_rerun_attempts(run_id, source_run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_attempt_source FOREIGN KEY (run_id, source_run_id) REFERENCES workflow_rerun_attempts(run_id, source_run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_authority FOREIGN KEY (tenant_id, checks_authority_id) REFERENCES github_server_service_authorities(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_manifest FOREIGN KEY (tenant_id, repository_id, provider_connection_id, provider_manifest_revision, provider_manifest_digest) REFERENCES github_provider_manifest_revisions(tenant_id, repository_id, provider_connection_id, manifest_revision, manifest_digest) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_contents_authority FOREIGN KEY (tenant_id, repository_contents_authority_id) REFERENCES github_server_service_authorities(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_request FOREIGN KEY (tenant_id, operation_id, run_id) REFERENCES workflow_rerun_requests(tenant_id, operation_id, rerun_run_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_source_subject FOREIGN KEY (tenant_id, source_github_check_subject_id) REFERENCES github_check_subjects(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_subject FOREIGN KEY (tenant_id, repository_id, provider_connection_id, run_id, github_check_subject_id) REFERENCES github_check_subjects(tenant_id, repository_id, provider_connection_id, workflow_rerun_run_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY workflow_rerun_check_evidence
    ADD CONSTRAINT workflow_rerun_check_evidence_tenant_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_actor_membership_fk FOREIGN KEY (tenant_id, actor_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_actor_session_fk FOREIGN KEY (tenant_id, actor_principal_id, actor_session_id) REFERENCES human_sessions(tenant_id, principal_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_attempt_source_fk FOREIGN KEY (rerun_run_id, source_run_id) REFERENCES workflow_rerun_attempts(run_id, source_run_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_repository_fk FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_rerun_fk FOREIGN KEY (repository_id, rerun_run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_selected_job_fk FOREIGN KEY (selected_source_job_id) REFERENCES logical_workflow_jobs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_selected_source_job_fk FOREIGN KEY (source_run_id, selected_source_job_id) REFERENCES logical_workflow_run_result_jobs(run_id, logical_job_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_source_fk FOREIGN KEY (repository_id, source_run_id) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_rerun_requests
    ADD CONSTRAINT workflow_rerun_requests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_run_number_counters
    ADD CONSTRAINT workflow_run_number_counters_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id) ON DELETE CASCADE;

ALTER TABLE ONLY workflow_runs
    ADD CONSTRAINT workflow_runs_concurrency_group_exists FOREIGN KEY (repository_id, concurrency_group_key) REFERENCES concurrency_groups(repository_id, normalized_key) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_runs
    ADD CONSTRAINT workflow_runs_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES workflow_snapshots(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_runs
    ADD CONSTRAINT workflow_runs_snapshot_matches_workflow FOREIGN KEY (snapshot_id, workflow_id) REFERENCES workflow_snapshots(id, workflow_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_runs
    ADD CONSTRAINT workflow_runs_workflow_matches_repository FOREIGN KEY (repository_id, workflow_id) REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_runtime_policy_current
    ADD CONSTRAINT workflow_runtime_policy_current_revision_fk FOREIGN KEY (tenant_id, repository_id, policy_revision) REFERENCES workflow_runtime_policy_revisions(tenant_id, repository_id, policy_revision) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_runtime_policy_features
    ADD CONSTRAINT workflow_runtime_policy_features_mapping_fk FOREIGN KEY (tenant_id, repository_id, policy_revision, selector) REFERENCES workflow_runtime_policy_mappings(tenant_id, repository_id, policy_revision, selector) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_runtime_policy_mappings
    ADD CONSTRAINT workflow_runtime_policy_mappings_revision_fk FOREIGN KEY (tenant_id, repository_id, policy_revision) REFERENCES workflow_runtime_policy_revisions(tenant_id, repository_id, policy_revision) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_runtime_policy_revisions
    ADD CONSTRAINT workflow_runtime_policy_revisions_repository_fk FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_snapshots
    ADD CONSTRAINT workflow_snapshots_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_variable_versions
    ADD CONSTRAINT workflow_variable_versions_creator FOREIGN KEY (tenant_id, created_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_variable_versions
    ADD CONSTRAINT workflow_variable_versions_variable FOREIGN KEY (tenant_id, variable_id) REFERENCES workflow_variables(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_variables
    ADD CONSTRAINT workflow_variables_creator FOREIGN KEY (tenant_id, created_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_variables
    ADD CONSTRAINT workflow_variables_current_version FOREIGN KEY (tenant_id, current_version_id, id, current_version_number) REFERENCES workflow_variable_versions(tenant_id, id, variable_id, version_number) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_variables
    ADD CONSTRAINT workflow_variables_environment FOREIGN KEY (tenant_id, repository_id, environment_id) REFERENCES repository_environments(tenant_id, repository_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_variables
    ADD CONSTRAINT workflow_variables_repository FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_variables
    ADD CONSTRAINT workflow_variables_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE ONLY workflow_variables
    ADD CONSTRAINT workflow_variables_updater FOREIGN KEY (tenant_id, updated_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT;
