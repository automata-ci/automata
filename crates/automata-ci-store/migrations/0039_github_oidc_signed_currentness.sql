-- Current-only signed GitHub OIDC authority.
--
-- The pre-0039 authority shape confused concrete JobIR permission evidence
-- with provider-authenticated source evidence. No authority or issuance slot
-- may be reinterpreted. Fresh authorities commit to the immutable 0037 run
-- receipt and every reservation/mint joins that receipt to the exact current
-- provider manifest, active service descriptors, materialized JobIR-v5, and
-- live attempt/session fence.

LOCK TABLE github_oidc_authorities IN ACCESS EXCLUSIVE MODE;
LOCK TABLE github_oidc_issuance_slots IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM github_oidc_authorities)
        OR EXISTS (SELECT 1 FROM github_oidc_issuance_slots)
    THEN
        RAISE EXCEPTION 'pre-signed-evidence GitHub OIDC state must be explicitly drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_oidc_signed_currentness_current_only';
    END IF;
END;
$automata$;

ALTER TABLE github_workflow_run_subject_evidence
    ADD CONSTRAINT github_workflow_run_subject_evidence_exact_digest_unique
    UNIQUE (repository_id, run_id, subject_evidence_sha256);

ALTER TABLE github_oidc_authorities
    DROP CONSTRAINT github_oidc_authorities_evidence_sha256,
    DROP CONSTRAINT github_oidc_authorities_subject_policy;

ALTER TABLE github_oidc_authorities
    RENAME COLUMN source_evidence_sha256
    TO github_run_subject_evidence_sha256;

ALTER TABLE github_oidc_authorities
    ALTER COLUMN github_owner_id SET NOT NULL,
    ADD CONSTRAINT github_oidc_authorities_current_evidence_sha256 CHECK (
        octet_length(plan_digest) = 32
        AND octet_length(event_digest) = 32
        AND octet_length(runtime_context_digest) = 32
        AND octet_length(permission_evidence_sha256) = 32
        AND permission_evidence_sha256 = job_ir_digest
        AND octet_length(subject_policy_sha256) = 32
        AND octet_length(github_run_subject_evidence_sha256) = 32
        AND octet_length(claim_evidence_sha256) = 32
        AND octet_length(configuration_sha256) = 32
        AND octet_length(request_bearer_sha256) = 32
        AND octet_length(request_bearer_key_sha256) = 32
    ),
    ADD CONSTRAINT github_oidc_authorities_stable_owner_policy CHECK (
        subject_policy_mode = 'stable_owner_evidence'
        AND subject_policy_revision > 0
        AND github_owner_id > 0
    ),
    ADD CONSTRAINT github_oidc_authorities_signed_run_evidence
        FOREIGN KEY (
            repository_id, run_id, github_run_subject_evidence_sha256
        ) REFERENCES github_workflow_run_subject_evidence(
            repository_id, run_id, subject_evidence_sha256
        ) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION automata_github_oidc_authority_is_current(
    authority github_oidc_authorities,
    observed_at_ms BIGINT,
    required_current_before_ms BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
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
        JOIN workflow_plan_v2_runs AS marker
          ON marker.run_id = run.id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = run.id
         AND invocation.id = authority.invocation_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = run.id
         AND logical_job.invocation_id = invocation.id
         AND logical_job.id = authority.logical_job_id
        JOIN workflow_plan_v2_instances AS instance
          ON instance.run_id = run.id
         AND instance.invocation_id = invocation.id
         AND instance.logical_job_id = logical_job.id
         AND instance.id = authority.instance_id
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.instance_id = instance.id
         AND concrete.run_id = run.id
         AND concrete.invocation_id = invocation.id
         AND concrete.logical_job_id = logical_job.id
         AND concrete.job_id = job.id
        JOIN workflow_plan_v2_materialization_claims AS materialization
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
        JOIN github_workflow_run_subject_evidence AS subject_evidence
          ON subject_evidence.tenant_id = authority.tenant_id
         AND subject_evidence.repository_id = authority.repository_id
         AND subject_evidence.workflow_id = authority.workflow_id
         AND subject_evidence.run_id = authority.run_id
         AND subject_evidence.root_invocation_id = authority.invocation_id
         AND subject_evidence.subject_evidence_sha256 =
             authority.github_run_subject_evidence_sha256
        JOIN github_provider_delivery_evidence AS delivery_evidence
          ON delivery_evidence.tenant_id = subject_evidence.tenant_id
         AND delivery_evidence.repository_id = subject_evidence.repository_id
         AND delivery_evidence.provider_delivery_id =
             subject_evidence.provider_delivery_id
        JOIN workflow_admission_receipts AS admission_receipt
          ON admission_receipt.tenant_id = subject_evidence.tenant_id
         AND admission_receipt.idempotency_kind = 'provider_delivery'
         AND admission_receipt.idempotency_key =
             subject_evidence.provider_delivery_idempotency_key
         AND admission_receipt.request_digest =
             subject_evidence.logical_admission_digest
         AND admission_receipt.repository_id = subject_evidence.repository_id
         AND admission_receipt.run_id = subject_evidence.run_id
         AND admission_receipt.committed_at_ms = subject_evidence.admitted_at_ms
         AND admission_receipt.github_subject_evidence_required
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery_evidence.tenant_id
         AND manifest.repository_id = delivery_evidence.repository_id
         AND manifest.provider_connection_id =
             delivery_evidence.provider_connection_id
         AND manifest.manifest_revision =
             delivery_evidence.provider_manifest_revision
         AND manifest.manifest_digest = delivery_evidence.provider_manifest_digest
        JOIN github_provider_manifest_current AS current_manifest
          ON current_manifest.tenant_id = manifest.tenant_id
         AND current_manifest.repository_id = manifest.repository_id
         AND current_manifest.provider_connection_id =
             manifest.provider_connection_id
         AND current_manifest.manifest_revision = manifest.manifest_revision
         AND current_manifest.manifest_digest = manifest.manifest_digest
        JOIN github_server_service_authorities AS checks_authority
          ON checks_authority.tenant_id = delivery_evidence.tenant_id
         AND checks_authority.id = delivery_evidence.checks_authority_id
         AND checks_authority.repository_id = delivery_evidence.repository_id
         AND checks_authority.provider_connection_id =
             delivery_evidence.provider_connection_id
         AND checks_authority.provider_installation_id =
             delivery_evidence.provider_installation_id
         AND checks_authority.github_repository_id =
             delivery_evidence.github_repository_id
         AND checks_authority.github_repository_name =
             delivery_evidence.github_repository_name
         AND checks_authority.service_scope = 'checks_write'
         AND checks_authority.identity_digest =
             delivery_evidence.checks_authority_identity_digest
         AND checks_authority.app_configuration_revision =
             delivery_evidence.checks_authority_app_configuration_revision
         AND checks_authority.policy_revision =
             delivery_evidence.checks_authority_policy_revision
        LEFT JOIN github_server_service_authorities AS private_authority
          ON private_authority.tenant_id = delivery_evidence.tenant_id
         AND private_authority.id = delivery_evidence.private_source_authority_id
         AND private_authority.repository_id = delivery_evidence.repository_id
         AND private_authority.provider_connection_id =
             delivery_evidence.provider_connection_id
         AND private_authority.provider_installation_id =
             delivery_evidence.provider_installation_id
         AND private_authority.github_repository_id =
             delivery_evidence.github_repository_id
         AND private_authority.github_repository_name =
             delivery_evidence.github_repository_name
         AND private_authority.service_scope =
             'private_repository_source_read'
         AND private_authority.identity_digest =
             delivery_evidence.private_source_authority_identity_digest
         AND private_authority.app_configuration_revision =
             delivery_evidence.private_source_authority_app_configuration_revision
         AND private_authority.policy_revision =
             delivery_evidence.private_source_authority_policy_revision
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
          AND job.admission_epoch = 4
          AND job.job_ir_schema = 5
          AND job.job_ir_schema = authority.job_ir_schema
          AND job.job_ir_size_bytes = authority.job_ir_size_bytes
          AND job.job_ir_digest = authority.job_ir_digest
          AND job.job_ir_object_key = authority.job_ir_object_key
          AND authority.permission_evidence_sha256 = authority.job_ir_digest
          AND job.requirements @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND run.plan_digest = authority.plan_digest
          AND run.plan_digest = subject_evidence.plan_digest
          AND run.event_digest = authority.event_digest
          AND run.event_digest = subject_evidence.event_digest
          AND run.snapshot_id = subject_evidence.snapshot_id
          AND run.head_sha = subject_evidence.github_check_head_sha
          AND run.event_name = subject_evidence.event_name
          AND run.git_ref = subject_evidence.git_ref
          AND run.status IN ('queued', 'in_progress')
          AND workflow.path = subject_evidence.workflow_path
          AND snapshot.source_digest = subject_evidence.source_digest
          AND marker.orchestration_schema = 1
          AND marker.root_invocation_id = subject_evidence.root_invocation_id
          AND marker.admission_digest = subject_evidence.logical_admission_digest
          AND marker.admitted_at_ms = subject_evidence.admitted_at_ms
          AND marker.state IN ('pending', 'active')
          AND invocation.plan_schema = 2
          AND invocation.plan_digest = authority.plan_digest
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND instance.job_ir_version = 5
          AND instance.job_ir_digest = authority.job_ir_digest
          AND instance.job_ir_object_key = authority.job_ir_object_key
          AND instance.job_ir_size_bytes = authority.job_ir_size_bytes
          AND concrete.runtime_context_schema = 2
          AND concrete.runtime_context_digest = authority.runtime_context_digest
          AND concrete.requirements = job.requirements
          AND materialization.state = 'materialized'
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id =
              delivery_evidence.github_repository_id::TEXT
          AND repository.owner || '/' || repository.name =
              delivery_evidence.github_repository_name
          AND authority.github_repository_id =
              delivery_evidence.github_repository_id
          AND authority.github_repository_name =
              delivery_evidence.github_repository_name
          AND authority.github_owner_id =
              delivery_evidence.github_repository_owner_id
          AND authority.subject_policy_mode = 'stable_owner_evidence'
          AND authority.subject_policy_revision > 0
          AND authority.subject = CASE
              WHEN subject_evidence.event_name = 'pull_request'
              THEN 'repo:' || delivery_evidence.github_repository_name ||
                   ':pull_request'
              ELSE 'repo:' || delivery_evidence.github_repository_name ||
                   ':ref:' || subject_evidence.git_ref
          END
          AND authority.default_audience = 'https://github.com/' ||
              split_part(delivery_evidence.github_repository_name, '/', 1)
          AND authority.additional_claims = jsonb_build_object(
              'event_name', subject_evidence.event_name,
              'ref', subject_evidence.git_ref,
              'repository', delivery_evidence.github_repository_name,
              'repository_owner',
                  split_part(delivery_evidence.github_repository_name, '/', 1),
              'run_attempt', run.run_attempt::TEXT,
              'run_number', run.run_number::TEXT,
              'runner_environment', 'self-hosted',
              'sha', encode(subject_evidence.github_check_head_sha, 'hex'),
              'workflow', run.workflow_name,
              'workflow_ref', delivery_evidence.github_repository_name || '/' ||
                  subject_evidence.workflow_path || '@' || subject_evidence.git_ref,
              'workflow_sha', encode(subject_evidence.github_check_head_sha, 'hex')
          )
          AND manifest.webhook_verifier_fingerprint_sha256 =
              delivery_evidence.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              delivery_evidence.authenticated_webhook_verifier_revision
          AND manifest.provider_installation_id =
              delivery_evidence.provider_installation_id
          AND manifest.github_repository_id =
              delivery_evidence.github_repository_id
          AND manifest.github_repository_name =
              delivery_evidence.github_repository_name
          AND manifest.repository_visibility =
              delivery_evidence.repository_visibility
          AND manifest.registered_at_ms <= observed_at_ms
          AND current_manifest.activated_at_ms <= observed_at_ms
          AND checks_authority.state = 'active'
          AND checks_authority.created_at_ms <= observed_at_ms
          AND checks_authority.state_updated_at_ms <= observed_at_ms
          AND (
              delivery_evidence.repository_visibility = 'public'
              AND delivery_evidence.private_source_authority_id IS NULL
              AND private_authority.id IS NULL
              OR delivery_evidence.repository_visibility = 'private'
              AND private_authority.id IS NOT NULL
              AND private_authority.state = 'active'
              AND private_authority.created_at_ms <= observed_at_ms
              AND private_authority.state_updated_at_ms <= observed_at_ms
          )
          AND subject_evidence.admitted_at_ms <= observed_at_ms
          AND authority.request_bearer_iat_seconds * 1000 <= observed_at_ms
          AND authority.request_bearer_exp_seconds * 1000 > observed_at_ms
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND runner.capabilities @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND session.job_ir_schema = 5
          AND session.capability_snapshot @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND session.disconnected_at_ms IS NULL
    )
$automata$;

CREATE OR REPLACE FUNCTION automata_lock_github_oidc_authority_dependencies(
    authority github_oidc_authorities
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $automata$
DECLARE
    delivery_visibility TEXT;
    private_authority_id UUID;
BEGIN
    SELECT delivery_evidence.repository_visibility,
           delivery_evidence.private_source_authority_id
      INTO delivery_visibility, private_authority_id
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
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
    JOIN workflow_plan_v2_invocations AS invocation
      ON invocation.run_id = run.id
     AND invocation.id = authority.invocation_id
    JOIN workflow_plan_v2_jobs AS logical_job
      ON logical_job.run_id = run.id
     AND logical_job.invocation_id = invocation.id
     AND logical_job.id = authority.logical_job_id
    JOIN workflow_plan_v2_instances AS instance
      ON instance.run_id = run.id
     AND instance.invocation_id = invocation.id
     AND instance.logical_job_id = logical_job.id
     AND instance.id = authority.instance_id
    JOIN workflow_plan_v2_concrete_jobs AS concrete
      ON concrete.instance_id = instance.id
     AND concrete.run_id = run.id
     AND concrete.invocation_id = invocation.id
     AND concrete.logical_job_id = logical_job.id
     AND concrete.job_id = job.id
    JOIN workflow_plan_v2_materialization_claims AS materialization
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
    JOIN github_workflow_run_subject_evidence AS subject_evidence
      ON subject_evidence.tenant_id = authority.tenant_id
     AND subject_evidence.repository_id = authority.repository_id
     AND subject_evidence.workflow_id = authority.workflow_id
     AND subject_evidence.run_id = authority.run_id
     AND subject_evidence.root_invocation_id = authority.invocation_id
     AND subject_evidence.subject_evidence_sha256 =
         authority.github_run_subject_evidence_sha256
    JOIN github_provider_delivery_evidence AS delivery_evidence
      ON delivery_evidence.tenant_id = subject_evidence.tenant_id
     AND delivery_evidence.repository_id = subject_evidence.repository_id
     AND delivery_evidence.provider_delivery_id =
         subject_evidence.provider_delivery_id
    JOIN workflow_admission_receipts AS admission_receipt
      ON admission_receipt.tenant_id = subject_evidence.tenant_id
     AND admission_receipt.idempotency_kind = 'provider_delivery'
     AND admission_receipt.idempotency_key =
         subject_evidence.provider_delivery_idempotency_key
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = delivery_evidence.tenant_id
     AND manifest.repository_id = delivery_evidence.repository_id
     AND manifest.provider_connection_id =
         delivery_evidence.provider_connection_id
     AND manifest.manifest_revision =
         delivery_evidence.provider_manifest_revision
     AND manifest.manifest_digest = delivery_evidence.provider_manifest_digest
    JOIN github_provider_manifest_current AS current_manifest
      ON current_manifest.tenant_id = manifest.tenant_id
     AND current_manifest.repository_id = manifest.repository_id
     AND current_manifest.provider_connection_id = manifest.provider_connection_id
     AND current_manifest.manifest_revision = manifest.manifest_revision
     AND current_manifest.manifest_digest = manifest.manifest_digest
    JOIN github_server_service_authorities AS checks_authority
      ON checks_authority.tenant_id = delivery_evidence.tenant_id
     AND checks_authority.id = delivery_evidence.checks_authority_id
     AND checks_authority.identity_digest =
         delivery_evidence.checks_authority_identity_digest
     AND checks_authority.app_configuration_revision =
         delivery_evidence.checks_authority_app_configuration_revision
     AND checks_authority.policy_revision =
         delivery_evidence.checks_authority_policy_revision
    WHERE attempt.id = authority.attempt_id
      AND materialization.state = 'materialized'
      AND checks_authority.state = 'active'
    FOR SHARE OF attempt, job, run, repository, workflow, snapshot, marker,
                 invocation, logical_job, instance, concrete, materialization,
                 runner, session,
                 subject_evidence, delivery_evidence, admission_receipt,
                 manifest, current_manifest, checks_authority;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF delivery_visibility = 'public' THEN
        RETURN private_authority_id IS NULL;
    END IF;
    IF delivery_visibility <> 'private' OR private_authority_id IS NULL THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM github_provider_delivery_evidence AS delivery_evidence
    JOIN github_server_service_authorities AS private_authority
      ON private_authority.tenant_id = delivery_evidence.tenant_id
     AND private_authority.id = delivery_evidence.private_source_authority_id
     AND private_authority.repository_id = delivery_evidence.repository_id
     AND private_authority.provider_connection_id =
         delivery_evidence.provider_connection_id
     AND private_authority.provider_installation_id =
         delivery_evidence.provider_installation_id
     AND private_authority.github_repository_id =
         delivery_evidence.github_repository_id
     AND private_authority.github_repository_name =
         delivery_evidence.github_repository_name
     AND private_authority.service_scope = 'private_repository_source_read'
     AND private_authority.identity_digest =
         delivery_evidence.private_source_authority_identity_digest
     AND private_authority.app_configuration_revision =
         delivery_evidence.private_source_authority_app_configuration_revision
     AND private_authority.policy_revision =
         delivery_evidence.private_source_authority_policy_revision
    WHERE delivery_evidence.tenant_id = authority.tenant_id
      AND delivery_evidence.repository_id = authority.repository_id
      AND delivery_evidence.private_source_authority_id = private_authority_id
      AND private_authority.state = 'active'
    FOR SHARE OF private_authority;
    RETURN FOUND;
END;
$automata$;
