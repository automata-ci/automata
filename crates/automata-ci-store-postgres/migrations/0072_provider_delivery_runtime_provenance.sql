-- Authenticated provider deliveries bind the exact manifest, admission receipt,
-- runtime policy, repository, and execution lineage without creating separate
-- GitHub subject-evidence rows. Keep that provider provenance authoritative for
-- runtime credentials while scheduled and rerun admissions retain their own
-- subject-evidence guards at admission.

CREATE OR REPLACE FUNCTION automata_github_runtime_authority_has_provenance(authority github_runtime_authority_issuances) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT automata_github_runtime_authority_has_selection_tails(authority)
       AND EXISTS (
        SELECT 1
        FROM github_workflow_run_manifest_origins AS origin
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS checks
          ON checks.tenant_id = origin.tenant_id
         AND checks.id = origin.checks_authority_id
         AND checks.repository_id = origin.repository_id
         AND checks.provider_connection_id = origin.provider_connection_id
         AND checks.provider_installation_id = origin.provider_installation_id
         AND checks.github_repository_id = origin.github_repository_id
         AND checks.github_repository_name = origin.github_repository_name
         AND checks.service_scope = 'checks_write'
         AND checks.identity_digest = origin.checks_authority_identity_digest
         AND checks.app_configuration_revision =
             origin.checks_authority_app_configuration_revision
         AND checks.policy_revision = origin.checks_authority_policy_revision
        JOIN github_server_service_authorities AS contents_authority
          ON contents_authority.tenant_id = origin.tenant_id
         AND contents_authority.id = origin.repository_contents_authority_id
         AND contents_authority.repository_id = origin.repository_id
         AND contents_authority.provider_connection_id =
             origin.provider_connection_id
         AND contents_authority.provider_installation_id =
             origin.provider_installation_id
         AND contents_authority.github_repository_id = origin.github_repository_id
         AND contents_authority.github_repository_name =
             origin.github_repository_name
         AND contents_authority.service_scope = 'repository_contents_read'
         AND contents_authority.identity_digest =
             origin.repository_contents_authority_identity_digest
         AND contents_authority.app_configuration_revision =
             origin.repository_contents_authority_app_configuration_revision
         AND contents_authority.policy_revision =
             origin.repository_contents_authority_policy_revision
        JOIN workflow_admission_receipts AS admission
          ON admission.tenant_id = origin.tenant_id
         AND admission.idempotency_kind = origin.admission_idempotency_kind
         AND admission.idempotency_key = origin.admission_idempotency_key
         AND admission.request_digest = origin.logical_admission_digest
         AND admission.repository_id = origin.repository_id
         AND admission.run_id = origin.run_id
         AND admission.committed_at_ms = origin.admitted_at_ms
        JOIN logical_workflow_runtime_policy_pins AS pin
          ON pin.run_id = origin.run_id
         AND pin.tenant_id = origin.tenant_id
         AND pin.repository_id = origin.repository_id
        JOIN workflow_runtime_policy_revisions AS policy
          ON policy.tenant_id = pin.tenant_id
         AND policy.repository_id = pin.repository_id
         AND policy.policy_revision = pin.policy_revision
         AND policy.policy_digest = pin.policy_digest
         AND policy.state = 'sealed'
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.job_id = authority.job_id
         AND concrete.run_id = authority.run_id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
         AND materialization.owner_id = concrete.claim_owner_id
         AND materialization.generation = concrete.claim_generation
         AND materialization.claimed_at_ms = concrete.claim_started_at_ms
         AND materialization.expires_at_ms = concrete.claim_expires_at_ms
         AND materialization.updated_at_ms = concrete.committed_at_ms
        JOIN logical_workflow_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN logical_workflow_activation_publications AS activation_publication
          ON activation_publication.run_id = instance.run_id
         AND activation_publication.invocation_id = instance.invocation_id
         AND activation_publication.logical_job_id = instance.logical_job_id
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = activation_publication.run_id
         AND preparation.invocation_id = activation_publication.invocation_id
         AND preparation.logical_job_id = activation_publication.logical_job_id
         AND preparation.activation_input_digest =
             activation_publication.activation_input_digest
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = preparation.run_id
         AND preparation_claim.invocation_id = preparation.invocation_id
         AND preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.descriptor_digest = preparation.descriptor_digest
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = concrete.run_id
         AND invocation.id = concrete.invocation_id
        JOIN logical_workflow_runs AS marker
          ON marker.run_id = concrete.run_id
        WHERE origin.tenant_id = authority.tenant_id
          AND origin.repository_id = authority.repository_id
          AND origin.run_id = authority.run_id
          AND origin.origin_kind IN (
              'provider_delivery', 'scheduled_fire', 'workflow_rerun'
          )
          AND contents_authority.github_app_id = manifest.github_app_id
          AND contents_authority.github_app_client_id =
              manifest.github_app_client_id
          AND contents_authority.github_app_jwt_issuer_kind =
              manifest.github_app_jwt_issuer_kind
          AND contents_authority.app_key_spki_sha256 =
              manifest.app_key_spki_sha256
          AND contents_authority.app_configuration_revision =
              manifest.app_configuration_revision
          AND contents_authority.policy_revision = manifest.policy_revision
          AND origin.provider_connection_id = authority.provider_connection_id
          AND origin.provider_installation_id =
              authority.provider_installation_id
          AND origin.github_repository_id = authority.github_repository_id
          AND origin.github_repository_name = authority.github_repository_name
          AND manifest.github_app_id = authority.github_app_id
          AND manifest.github_app_client_id = authority.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind =
              authority.github_app_jwt_issuer_kind
          AND authority.github_app_jwt_issuer_value =
              CASE manifest.github_app_jwt_issuer_kind
                  WHEN 'app_client_id' THEN manifest.github_app_client_id
                  WHEN 'app_id' THEN manifest.github_app_id::TEXT
              END
          AND manifest.app_key_spki_sha256 = authority.issuer_fingerprint
          AND manifest.github_app_id = checks.github_app_id
          AND manifest.github_app_client_id = checks.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind =
              checks.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = checks.app_key_spki_sha256
          AND manifest.app_configuration_revision =
              checks.app_configuration_revision
          AND manifest.policy_revision = checks.policy_revision
          AND checks.configuration_fingerprint =
              authority.configuration_fingerprint
          AND marker.root_invocation_id = origin.root_invocation_id
          AND marker.admission_digest = origin.logical_admission_digest
          AND marker.admitted_at_ms = origin.admitted_at_ms
          AND automata_logical_workflow_invocation_published(
              concrete.run_id, concrete.invocation_id
          )
          AND invocation.plan_schema = 1
          AND manifest.runtime_policy_revision = pin.policy_revision
          AND manifest.runtime_policy_digest = pin.policy_digest
          AND manifest.runner_policy_digest =
              pg_catalog.sha256(policy.canonical_policy)
          AND manifest.runner_policy_object_key = 'github/runner-policy/v1/'
              || pg_catalog.encode(manifest.runner_policy_digest, 'hex') || '.json'
          AND manifest.runner_policy_size_bytes =
              pg_catalog.octet_length(policy.canonical_policy)
          AND manifest.runner_policy_media_type =
              'application/vnd.automata.github-runner-policy+json'
          AND logical_job.runtime_policy_revision = pin.policy_revision
          AND logical_job.runtime_policy_digest = pin.policy_digest
          AND preparation_claim.runtime_policy_revision = pin.policy_revision
          AND preparation_claim.runtime_policy_digest = pin.policy_digest
          AND preparation_claim.runner_policy_digest =
              manifest.runner_policy_digest
          AND preparation_claim.runner_policy_object_key =
              manifest.runner_policy_object_key
          AND preparation_claim.runner_policy_size_bytes =
              manifest.runner_policy_size_bytes
          AND preparation_claim.runner_policy_media_type =
              manifest.runner_policy_media_type
          AND preparation.runtime_policy_revision = pin.policy_revision
          AND preparation.runtime_policy_digest = pin.policy_digest
          AND activation_publication.runtime_policy_revision = pin.policy_revision
          AND activation_publication.runtime_policy_digest = pin.policy_digest
          AND instance.runtime_policy_revision = pin.policy_revision
          AND instance.runtime_policy_digest = pin.policy_digest
          AND materialization.runtime_policy_revision = pin.policy_revision
          AND materialization.runtime_policy_digest = pin.policy_digest
          AND concrete.runtime_policy_revision = pin.policy_revision
          AND concrete.runtime_policy_digest = pin.policy_digest
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND activation_publication.authority_profile = 'standard'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
    )
$$;

CREATE OR REPLACE FUNCTION automata_workload_oidc_authority_is_current(authority workload_oidc_authorities, observed_at_ms bigint, required_current_before_ms bigint) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT EXISTS (
        SELECT 1
        FROM job_attempts AS attempt
        JOIN jobs AS job
          ON job.id = attempt.job_id
         AND job.id = authority.job_id
         AND job.run_id = authority.run_id
        JOIN workflow_runs AS run
          ON run.id = job.run_id
         AND run.id = authority.run_id
         AND run.repository_id = authority.repository_id
         AND run.workflow_id = authority.workflow_id
        JOIN repositories AS repository
          ON repository.id = run.repository_id
         AND repository.id = authority.repository_id
         AND repository.tenant_id = authority.tenant_id
        JOIN workflow_definitions AS workflow
          ON workflow.id = run.workflow_id
         AND workflow.repository_id = run.repository_id
        JOIN workflow_snapshots AS snapshot
          ON snapshot.id = run.snapshot_id
         AND snapshot.workflow_id = run.workflow_id
        JOIN logical_workflow_runs AS marker
          ON marker.run_id = run.id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = run.id
         AND invocation.id = authority.invocation_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = run.id
         AND logical_job.invocation_id = invocation.id
         AND logical_job.id = authority.logical_job_id
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = logical_job.run_id
         AND preparation_claim.invocation_id = logical_job.invocation_id
         AND preparation_claim.logical_job_id = logical_job.id
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = preparation_claim.run_id
         AND preparation.invocation_id = preparation_claim.invocation_id
         AND preparation.logical_job_id = preparation_claim.logical_job_id
         AND preparation.descriptor_digest = preparation_claim.descriptor_digest
        JOIN logical_workflow_activation_publications AS activation_publication
          ON activation_publication.run_id = logical_job.run_id
         AND activation_publication.invocation_id = logical_job.invocation_id
         AND activation_publication.logical_job_id = logical_job.id
         AND activation_publication.activation_input_digest =
             preparation.activation_input_digest
        JOIN logical_workflow_instances AS instance
          ON instance.run_id = run.id
         AND instance.invocation_id = invocation.id
         AND instance.logical_job_id = logical_job.id
         AND instance.id = authority.instance_id
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.instance_id = instance.id
         AND concrete.run_id = run.id
         AND concrete.invocation_id = invocation.id
         AND concrete.logical_job_id = logical_job.id
         AND concrete.job_id = job.id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
         AND materialization.owner_id = concrete.claim_owner_id
         AND materialization.generation = concrete.claim_generation
         AND materialization.claimed_at_ms = concrete.claim_started_at_ms
         AND materialization.expires_at_ms = concrete.claim_expires_at_ms
         AND materialization.updated_at_ms = concrete.committed_at_ms
        JOIN runners AS runner
          ON runner.id = attempt.runner_id
         AND runner.id = authority.runner_id
         AND runner.tenant_id = authority.tenant_id
         AND runner.generation = authority.runner_generation
         AND runner.session_epoch = authority.runner_session_epoch
        JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.id = authority.runner_session_id
         AND session.runner_id = authority.runner_id
         AND session.session_epoch = authority.runner_session_epoch
         AND session.runner_generation = authority.runner_generation
        JOIN github_workflow_run_manifest_origins AS origin
          ON origin.tenant_id = authority.tenant_id
         AND origin.repository_id = authority.repository_id
         AND origin.workflow_id = authority.workflow_id
         AND origin.run_id = authority.run_id
         AND origin.root_invocation_id = marker.root_invocation_id
         AND origin.subject_evidence_sha256 =
             authority.github_run_subject_evidence_sha256
        JOIN workflow_admission_receipts AS admission_receipt
          ON admission_receipt.tenant_id = origin.tenant_id
         AND admission_receipt.idempotency_kind =
             origin.admission_idempotency_kind
         AND admission_receipt.idempotency_key =
             origin.admission_idempotency_key
         AND admission_receipt.request_digest = origin.logical_admission_digest
         AND admission_receipt.repository_id = origin.repository_id
         AND admission_receipt.run_id = origin.run_id
         AND admission_receipt.committed_at_ms = origin.admitted_at_ms
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS checks_authority
          ON checks_authority.tenant_id = origin.tenant_id
         AND checks_authority.id = origin.checks_authority_id
         AND checks_authority.repository_id = origin.repository_id
         AND checks_authority.provider_connection_id =
             origin.provider_connection_id
         AND checks_authority.provider_installation_id =
             origin.provider_installation_id
         AND checks_authority.github_repository_id =
             origin.github_repository_id
         AND checks_authority.github_repository_name =
             origin.github_repository_name
         AND checks_authority.service_scope = 'checks_write'
         AND checks_authority.identity_digest =
             origin.checks_authority_identity_digest
         AND checks_authority.app_configuration_revision =
             origin.checks_authority_app_configuration_revision
         AND checks_authority.policy_revision =
             origin.checks_authority_policy_revision
        JOIN github_server_service_authorities AS contents_authority
          ON contents_authority.tenant_id = origin.tenant_id
         AND contents_authority.id = origin.repository_contents_authority_id
         AND contents_authority.repository_id = origin.repository_id
         AND contents_authority.provider_connection_id =
             origin.provider_connection_id
         AND contents_authority.provider_installation_id =
             origin.provider_installation_id
         AND contents_authority.github_repository_id =
             origin.github_repository_id
         AND contents_authority.github_repository_name =
             origin.github_repository_name
         AND contents_authority.service_scope =
             'repository_contents_read'
         AND contents_authority.identity_digest =
             origin.repository_contents_authority_identity_digest
         AND contents_authority.app_configuration_revision =
             origin.repository_contents_authority_app_configuration_revision
         AND contents_authority.policy_revision =
             origin.repository_contents_authority_policy_revision
        WHERE attempt.id = authority.attempt_id
          AND attempt.job_id = authority.job_id
          AND attempt.attempt_number = authority.attempt_number
          AND attempt.fencing_token = authority.fencing_token
          AND attempt.lease_id = authority.lease_id
          AND attempt.lease_issued_at_ms = authority.lease_issued_at_ms
          AND attempt.lease_expires_at_ms >= authority.lease_expires_at_ms
          AND required_current_before_ms > observed_at_ms
          AND attempt.lease_expires_at_ms >= required_current_before_ms
          AND attempt.runner_id = authority.runner_id
          AND attempt.runner_session_id = authority.runner_session_id
          AND attempt.runner_session_epoch = authority.runner_session_epoch
          AND attempt.runner_generation = authority.runner_generation
          AND attempt.runner_slot = authority.runner_slot
          AND attempt.lifecycle IN ('leased', 'preparing', 'running')
          AND attempt.changed_at_ms <= observed_at_ms
          AND job.admission_epoch = 1
          AND job.job_ir_schema = 1
          AND job.job_ir_schema = authority.job_ir_schema
          AND job.job_ir_size_bytes = authority.job_ir_size_bytes
          AND job.job_ir_digest = authority.job_ir_digest
          AND job.job_ir_object_key = authority.job_ir_object_key
          AND authority.permission_evidence_sha256 = authority.job_ir_digest
          AND job.requirements @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
          AND (
              invocation.id <> marker.root_invocation_id
              OR run.plan_digest = authority.plan_digest
          )
          AND run.plan_digest = origin.plan_digest
          AND run.event_digest = authority.event_digest
          AND run.event_digest = origin.event_digest
          AND run.snapshot_id = origin.snapshot_id
          AND run.head_sha = origin.github_check_head_sha
          AND run.event_name = origin.event_name
          AND run.git_ref = origin.git_ref
          AND run.status IN ('queued', 'in_progress')
          AND (
              origin.origin_kind = 'provider_delivery'
              AND origin.admission_idempotency_kind = 'provider_delivery'
              OR origin.origin_kind IN ('scheduled_fire', 'workflow_rerun')
              AND origin.admission_idempotency_kind = 'operation'
          )
          AND workflow.path = origin.workflow_path
          AND snapshot.source_digest = origin.source_digest
          AND marker.orchestration_schema = 1
          AND marker.root_invocation_id = origin.root_invocation_id
          AND marker.admission_digest = origin.logical_admission_digest
          AND marker.admitted_at_ms = origin.admitted_at_ms
          AND marker.state IN ('pending', 'active')
          AND automata_logical_workflow_invocation_published(
              run.id, invocation.id
          )
          AND automata_reusable_workflow_oidc_permission_authorized(
              run.id, invocation.id
          )
          AND invocation.plan_schema = 1
          AND invocation.plan_digest = authority.plan_digest
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND instance.job_ir_version = 1
          AND instance.job_ir_digest = authority.job_ir_digest
          AND instance.job_ir_object_key = authority.job_ir_object_key
          AND instance.job_ir_size_bytes = authority.job_ir_size_bytes
          AND concrete.runtime_context_schema = 1
          AND concrete.runtime_context_digest = authority.runtime_context_digest
          AND concrete.requirements = job.requirements
          AND materialization.state = 'materialized'
          AND logical_job.activation_input_digest =
              preparation.activation_input_digest
          AND preparation_claim.state = 'prepared'
          AND activation_publication.condition_matched
          AND activation_publication.job_ir_version = 1
          AND activation_publication.runtime_context_schema = 1
          AND manifest.authority_profile = 'standard'
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND activation_publication.authority_profile = 'standard'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id =
              origin.github_repository_id::TEXT
          AND repository.owner || '/' || repository.name =
              origin.github_repository_name
          AND authority.github_repository_id =
              origin.github_repository_id
          AND authority.github_repository_name =
              origin.github_repository_name
          AND authority.github_owner_id =
              origin.github_repository_owner_id
          AND authority.subject_policy_mode = 'stable_owner_evidence'
          AND authority.subject_policy_revision > 0
          AND authority.subject = CASE
              WHEN origin.event_name = 'pull_request'
              THEN 'repo:' || origin.github_repository_name ||
                   ':pull_request'
              ELSE 'repo:' || origin.github_repository_name ||
                   ':ref:' || origin.git_ref
          END
          AND authority.default_audience = 'https://github.com/' ||
              split_part(origin.github_repository_name, '/', 1)
          AND authority.additional_claims = jsonb_build_object(
              'event_name', origin.event_name,
              'ref', origin.git_ref,
              'repository', origin.github_repository_name,
              'repository_owner',
                  split_part(origin.github_repository_name, '/', 1),
              'run_attempt', run.run_attempt::TEXT,
              'run_number', run.run_number::TEXT,
              'runner_environment', 'self-hosted',
              'sha', encode(origin.github_check_head_sha, 'hex'),
              'workflow', run.workflow_name,
              'workflow_ref', origin.github_repository_name || '/' ||
                  origin.workflow_path || '@' || origin.git_ref,
              'workflow_sha', encode(origin.github_check_head_sha, 'hex')
          )
          AND manifest.webhook_verifier_fingerprint_sha256 =
              origin.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              origin.authenticated_webhook_verifier_revision
          AND manifest.provider_installation_id =
              origin.provider_installation_id
          AND manifest.github_repository_id =
              origin.github_repository_id
          AND manifest.github_repository_name =
              origin.github_repository_name
          AND manifest.repository_visibility =
              origin.repository_visibility
          AND manifest.registered_at_ms <= observed_at_ms
          AND checks_authority.state = 'active'
          AND checks_authority.created_at_ms <= observed_at_ms
          AND checks_authority.state_updated_at_ms <= observed_at_ms
          AND contents_authority.state = 'active'
          AND contents_authority.created_at_ms <= observed_at_ms
          AND contents_authority.state_updated_at_ms <= observed_at_ms
          AND origin.admitted_at_ms <= observed_at_ms
          AND authority.request_bearer_iat_seconds * 1000 <= observed_at_ms
          AND authority.request_bearer_exp_seconds * 1000 > observed_at_ms
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND runner.capabilities @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND session.job_ir_schema = 1
          AND session.capability_snapshot @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND session.disconnected_at_ms IS NULL
    )
$$;

CREATE OR REPLACE FUNCTION automata_lock_workload_oidc_authority_dependencies(authority workload_oidc_authorities) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    contents_authority_id UUID;
BEGIN
    SELECT origin.repository_contents_authority_id
      INTO contents_authority_id
    FROM job_attempts AS attempt
    JOIN jobs AS job
      ON job.id = attempt.job_id
     AND job.id = authority.job_id
     AND job.run_id = authority.run_id
    JOIN workflow_runs AS run
      ON run.id = job.run_id
     AND run.id = authority.run_id
     AND run.repository_id = authority.repository_id
    JOIN repositories AS repository
      ON repository.id = run.repository_id
     AND repository.tenant_id = authority.tenant_id
    JOIN workflow_definitions AS workflow
      ON workflow.id = run.workflow_id
     AND workflow.repository_id = run.repository_id
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
    JOIN logical_workflow_invocations AS invocation
      ON invocation.run_id = run.id
     AND invocation.id = authority.invocation_id
    JOIN logical_workflow_jobs AS logical_job
      ON logical_job.run_id = run.id
     AND logical_job.invocation_id = invocation.id
     AND logical_job.id = authority.logical_job_id
    JOIN logical_workflow_activation_preparation_claims AS preparation_claim
      ON preparation_claim.run_id = logical_job.run_id
     AND preparation_claim.invocation_id = logical_job.invocation_id
     AND preparation_claim.logical_job_id = logical_job.id
    JOIN logical_workflow_activation_preparations AS preparation
      ON preparation.run_id = preparation_claim.run_id
     AND preparation.invocation_id = preparation_claim.invocation_id
     AND preparation.logical_job_id = preparation_claim.logical_job_id
     AND preparation.descriptor_digest = preparation_claim.descriptor_digest
    JOIN logical_workflow_activation_publications AS activation_publication
      ON activation_publication.run_id = logical_job.run_id
     AND activation_publication.invocation_id = logical_job.invocation_id
     AND activation_publication.logical_job_id = logical_job.id
     AND activation_publication.activation_input_digest =
         preparation.activation_input_digest
    JOIN logical_workflow_instances AS instance
      ON instance.run_id = run.id
     AND instance.invocation_id = invocation.id
     AND instance.logical_job_id = logical_job.id
     AND instance.id = authority.instance_id
    JOIN logical_workflow_concrete_jobs AS concrete
      ON concrete.instance_id = instance.id
     AND concrete.run_id = run.id
     AND concrete.invocation_id = invocation.id
     AND concrete.logical_job_id = logical_job.id
     AND concrete.job_id = job.id
    JOIN logical_workflow_materialization_claims AS materialization
      ON materialization.instance_id = concrete.instance_id
     AND materialization.run_id = concrete.run_id
     AND materialization.invocation_id = concrete.invocation_id
     AND materialization.logical_job_id = concrete.logical_job_id
     AND materialization.descriptor_digest = concrete.descriptor_digest
     AND materialization.expected_job_id = concrete.job_id
     AND materialization.expected_attempt_id = concrete.initial_attempt_id
     AND materialization.owner_id = concrete.claim_owner_id
     AND materialization.generation = concrete.claim_generation
     AND materialization.claimed_at_ms = concrete.claim_started_at_ms
     AND materialization.expires_at_ms = concrete.claim_expires_at_ms
     AND materialization.updated_at_ms = concrete.committed_at_ms
    JOIN runners AS runner
      ON runner.id = attempt.runner_id
     AND runner.id = authority.runner_id
     AND runner.tenant_id = authority.tenant_id
    JOIN runner_sessions AS session
      ON session.id = attempt.runner_session_id
     AND session.id = authority.runner_session_id
     AND session.runner_id = authority.runner_id
    JOIN github_workflow_run_manifest_origins AS origin
      ON origin.tenant_id = authority.tenant_id
     AND origin.repository_id = authority.repository_id
     AND origin.workflow_id = authority.workflow_id
     AND origin.run_id = authority.run_id
     AND origin.root_invocation_id = marker.root_invocation_id
     AND origin.subject_evidence_sha256 =
         authority.github_run_subject_evidence_sha256
    JOIN workflow_admission_receipts AS admission_receipt
      ON admission_receipt.tenant_id = origin.tenant_id
     AND admission_receipt.idempotency_kind =
         origin.admission_idempotency_kind
     AND admission_receipt.idempotency_key =
         origin.admission_idempotency_key
     AND admission_receipt.request_digest = origin.logical_admission_digest
     AND admission_receipt.repository_id = origin.repository_id
     AND admission_receipt.run_id = origin.run_id
     AND admission_receipt.committed_at_ms = origin.admitted_at_ms
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = origin.tenant_id
     AND manifest.repository_id = origin.repository_id
     AND manifest.provider_connection_id = origin.provider_connection_id
     AND manifest.manifest_revision = origin.provider_manifest_revision
     AND manifest.manifest_digest = origin.provider_manifest_digest
    JOIN github_server_service_authorities AS checks_authority
      ON checks_authority.tenant_id = origin.tenant_id
     AND checks_authority.id = origin.checks_authority_id
     AND checks_authority.repository_id = origin.repository_id
     AND checks_authority.provider_connection_id = origin.provider_connection_id
     AND checks_authority.provider_installation_id =
         origin.provider_installation_id
     AND checks_authority.github_repository_id = origin.github_repository_id
     AND checks_authority.github_repository_name =
         origin.github_repository_name
     AND checks_authority.service_scope = 'checks_write'
     AND checks_authority.identity_digest =
         origin.checks_authority_identity_digest
     AND checks_authority.app_configuration_revision =
         origin.checks_authority_app_configuration_revision
     AND checks_authority.policy_revision =
         origin.checks_authority_policy_revision
    WHERE attempt.id = authority.attempt_id
      AND materialization.state = 'materialized'
      AND (
          origin.origin_kind = 'provider_delivery'
          AND origin.admission_idempotency_kind = 'provider_delivery'
          OR origin.origin_kind IN ('scheduled_fire', 'workflow_rerun')
          AND origin.admission_idempotency_kind = 'operation'
      )
      AND logical_job.activation_input_digest = preparation.activation_input_digest
      AND preparation_claim.state = 'prepared'
      AND activation_publication.condition_matched
      AND automata_logical_workflow_invocation_published(
          run.id, invocation.id
      )
      AND automata_reusable_workflow_oidc_permission_authorized(
          run.id, invocation.id
      )
      AND manifest.authority_profile = 'standard'
      AND logical_job.authority_profile = 'standard'
      AND preparation_claim.authority_profile = 'standard'
      AND preparation.authority_profile = 'standard'
      AND activation_publication.authority_profile = 'standard'
      AND materialization.authority_profile = 'standard'
      AND concrete.authority_profile = 'standard'
      AND checks_authority.state = 'active'
    FOR SHARE OF attempt, job, run, repository, workflow, snapshot, marker,
                 invocation, logical_job, preparation_claim, preparation,
                 activation_publication, instance, concrete, materialization,
                 runner, session,
                 admission_receipt, manifest, checks_authority;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF contents_authority_id IS NULL THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM github_workflow_run_manifest_origins AS origin
    JOIN github_server_service_authorities AS contents_authority
      ON contents_authority.tenant_id = origin.tenant_id
     AND contents_authority.id = origin.repository_contents_authority_id
     AND contents_authority.repository_id = origin.repository_id
     AND contents_authority.provider_connection_id =
         origin.provider_connection_id
     AND contents_authority.provider_installation_id =
         origin.provider_installation_id
     AND contents_authority.github_repository_id =
         origin.github_repository_id
     AND contents_authority.github_repository_name =
         origin.github_repository_name
     AND contents_authority.service_scope = 'repository_contents_read'
     AND contents_authority.identity_digest =
         origin.repository_contents_authority_identity_digest
     AND contents_authority.app_configuration_revision =
         origin.repository_contents_authority_app_configuration_revision
     AND contents_authority.policy_revision =
         origin.repository_contents_authority_policy_revision
    WHERE origin.tenant_id = authority.tenant_id
      AND origin.repository_id = authority.repository_id
      AND origin.workflow_id = authority.workflow_id
      AND origin.run_id = authority.run_id
      AND origin.subject_evidence_sha256 =
          authority.github_run_subject_evidence_sha256
      AND origin.repository_contents_authority_id = contents_authority_id
      AND contents_authority.state = 'active'
    FOR SHARE OF contents_authority;
    RETURN FOUND;
END;
$$;


