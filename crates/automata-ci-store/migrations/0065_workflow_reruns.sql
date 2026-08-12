-- Durable workflow reruns create a new physical workflow-run row for every
-- attempt while retaining the provider-visible identity of attempt one.  No
-- mutable provider/source fetch participates in this operation: all source,
-- plan, event, policy, and result identities are copied from immutable rows.

CREATE FUNCTION automata_workflow_rerun_now_ms()
RETURNS BIGINT
LANGUAGE SQL
STABLE
PARALLEL SAFE
AS $automata$
    SELECT floor(extract(epoch FROM transaction_timestamp()) * 1000)::BIGINT
$automata$;

ALTER TABLE workflow_runs
    ADD COLUMN public_run_id_alias BIGINT,
    ADD COLUMN triggering_actor TEXT,
    ADD COLUMN concurrency_cancel_in_progress BOOLEAN,
    ADD CONSTRAINT workflow_runs_public_id_alias_positive CHECK (
        public_run_id_alias IS NULL
        OR public_run_id_alias BETWEEN 1 AND 9007199254740991
    ),
    ADD CONSTRAINT workflow_runs_triggering_actor_shape CHECK (
        triggering_actor IS NULL OR (
            octet_length(triggering_actor) BETWEEN 1 AND 1024
            AND triggering_actor !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT workflow_runs_concurrency_cancel_shape CHECK (
        concurrency_group_key IS NOT NULL
        OR concurrency_cancel_in_progress IS NULL
    );

-- Normal admissions continue to omit the provider-visible alias.  Identity
-- defaults are populated before row triggers, so a first-attempt insert can
-- derive its public identity from the newly allocated internal alias while a
-- rerun can provide the attempt-one alias explicitly.
CREATE FUNCTION automata_default_workflow_public_run_id_alias()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.public_run_id_alias IS NULL THEN
        NEW.public_run_id_alias := NEW.run_id_alias;
    END IF;
    RETURN NEW;
END;
$automata$;

-- Rerun origins are introduced by this migration, so the reusable/OIDC
-- predicates originally installed by 0063 are replaced forward-only here.
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
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = logical_job.run_id
         AND preparation_claim.invocation_id = logical_job.invocation_id
         AND preparation_claim.logical_job_id = logical_job.id
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.run_id = preparation_claim.run_id
         AND preparation.invocation_id = preparation_claim.invocation_id
         AND preparation.logical_job_id = preparation_claim.logical_job_id
         AND preparation.descriptor_digest = preparation_claim.descriptor_digest
        JOIN workflow_plan_v2_activation_publications AS activation_publication
          ON activation_publication.run_id = logical_job.run_id
         AND activation_publication.invocation_id = logical_job.invocation_id
         AND activation_publication.logical_job_id = logical_job.id
         AND activation_publication.activation_input_digest =
             preparation.activation_input_digest
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
         AND admission_receipt.github_subject_evidence_required
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
        LEFT JOIN github_server_service_authorities AS private_authority
          ON private_authority.tenant_id = origin.tenant_id
         AND private_authority.id = origin.private_source_authority_id
         AND private_authority.repository_id = origin.repository_id
         AND private_authority.provider_connection_id =
             origin.provider_connection_id
         AND private_authority.provider_installation_id =
             origin.provider_installation_id
         AND private_authority.github_repository_id =
             origin.github_repository_id
         AND private_authority.github_repository_name =
             origin.github_repository_name
         AND private_authority.service_scope =
             'private_repository_source_read'
         AND private_authority.identity_digest =
             origin.private_source_authority_identity_digest
         AND private_authority.app_configuration_revision =
             origin.private_source_authority_app_configuration_revision
         AND private_authority.policy_revision =
             origin.private_source_authority_policy_revision
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
          AND automata_workflow_plan_v2_invocation_published(
              run.id, invocation.id
          )
          AND automata_reusable_workflow_oidc_permission_authorized(
              run.id, invocation.id
          )
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
          AND logical_job.activation_input_digest =
              preparation.activation_input_digest
          AND preparation_claim.state = 'prepared'
          AND activation_publication.condition_matched
          AND activation_publication.job_ir_version = 5
          AND activation_publication.runtime_context_schema = 2
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
                  regexp_replace(
                      origin.workflow_path,
                      '^\.ci/workflows/', '.github/workflows/'
                  ) || '@' || origin.git_ref,
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
          AND (
              origin.repository_visibility = 'public'
              AND origin.private_source_authority_id IS NULL
              AND private_authority.id IS NULL
              OR origin.repository_visibility = 'private'
              AND private_authority.id IS NOT NULL
              AND private_authority.state = 'active'
              AND private_authority.created_at_ms <= observed_at_ms
              AND private_authority.state_updated_at_ms <= observed_at_ms
          )
          AND origin.admitted_at_ms <= observed_at_ms
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

-- The insert-time profile guard now follows root subject evidence to a sealed
-- child and enforces the child's exact id-token ceiling before an authority row
-- can exist. This also protects direct SQL writers that bypass the adapter.
CREATE OR REPLACE FUNCTION automata_require_standard_github_oidc_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM github_workflow_run_manifest_origins AS origin
        JOIN workflow_plan_v2_runs AS marker
          ON marker.run_id = origin.run_id
         AND marker.root_invocation_id = origin.root_invocation_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.instance_id = NEW.instance_id
         AND concrete.run_id = NEW.run_id
         AND concrete.invocation_id = NEW.invocation_id
         AND concrete.logical_job_id = NEW.logical_job_id
         AND concrete.job_id = NEW.job_id
         AND concrete.initial_attempt_id = NEW.attempt_id
        WHERE origin.tenant_id = NEW.tenant_id
          AND origin.repository_id = NEW.repository_id
          AND origin.workflow_id = NEW.workflow_id
          AND origin.run_id = NEW.run_id
          AND origin.subject_evidence_sha256 =
              NEW.github_run_subject_evidence_sha256
          AND (
              origin.origin_kind = 'provider_delivery'
              AND origin.admission_idempotency_kind = 'provider_delivery'
              OR origin.origin_kind IN ('scheduled_fire', 'workflow_rerun')
              AND origin.admission_idempotency_kind = 'operation'
          )
          AND automata_workflow_plan_v2_invocation_published(
              NEW.run_id, NEW.invocation_id
          )
          AND automata_reusable_workflow_oidc_permission_authorized(
              NEW.run_id, NEW.invocation_id
          )
          AND manifest.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
    ) THEN
        RAISE EXCEPTION 'GitHub-compatible OIDC requires historical Standard authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'github_oidc_historical_standard_authority';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Lock the same historical dependency graph for a root or a sealed child.
-- The permission helper is evaluated while these graph rows remain share
-- locked; publication and permission evidence are immutable after insertion.
CREATE OR REPLACE FUNCTION automata_lock_github_oidc_authority_dependencies(
    authority github_oidc_authorities
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $automata$
DECLARE
    origin_visibility TEXT;
    private_authority_id UUID;
BEGIN
    SELECT origin.repository_visibility,
           origin.private_source_authority_id
      INTO origin_visibility, private_authority_id
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
    JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
      ON preparation_claim.run_id = logical_job.run_id
     AND preparation_claim.invocation_id = logical_job.invocation_id
     AND preparation_claim.logical_job_id = logical_job.id
    JOIN workflow_plan_v2_activation_preparations AS preparation
      ON preparation.run_id = preparation_claim.run_id
     AND preparation.invocation_id = preparation_claim.invocation_id
     AND preparation.logical_job_id = preparation_claim.logical_job_id
     AND preparation.descriptor_digest = preparation_claim.descriptor_digest
    JOIN workflow_plan_v2_activation_publications AS activation_publication
      ON activation_publication.run_id = logical_job.run_id
     AND activation_publication.invocation_id = logical_job.invocation_id
     AND activation_publication.logical_job_id = logical_job.id
     AND activation_publication.activation_input_digest =
         preparation.activation_input_digest
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
     AND admission_receipt.github_subject_evidence_required
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
      AND automata_workflow_plan_v2_invocation_published(
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

    IF origin_visibility = 'public' THEN
        RETURN private_authority_id IS NULL;
    END IF;
    IF origin_visibility <> 'private' OR private_authority_id IS NULL THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM github_workflow_run_manifest_origins AS origin
    JOIN github_server_service_authorities AS private_authority
      ON private_authority.tenant_id = origin.tenant_id
     AND private_authority.id = origin.private_source_authority_id
     AND private_authority.repository_id = origin.repository_id
     AND private_authority.provider_connection_id =
         origin.provider_connection_id
     AND private_authority.provider_installation_id =
         origin.provider_installation_id
     AND private_authority.github_repository_id =
         origin.github_repository_id
     AND private_authority.github_repository_name =
         origin.github_repository_name
     AND private_authority.service_scope = 'private_repository_source_read'
     AND private_authority.identity_digest =
         origin.private_source_authority_identity_digest
     AND private_authority.app_configuration_revision =
         origin.private_source_authority_app_configuration_revision
     AND private_authority.policy_revision =
         origin.private_source_authority_policy_revision
    WHERE origin.tenant_id = authority.tenant_id
      AND origin.repository_id = authority.repository_id
      AND origin.workflow_id = authority.workflow_id
      AND origin.run_id = authority.run_id
      AND origin.subject_evidence_sha256 =
          authority.github_run_subject_evidence_sha256
      AND origin.private_source_authority_id = private_authority_id
      AND private_authority.state = 'active'
    FOR SHARE OF private_authority;
    RETURN FOUND;
END;
$automata$;

-- 0044 retained the 0041 predicate under this internal name. Generalize only
-- its invocation/subject binding; every mutable lease, manifest, runner,
-- runtime-policy, and materialization fence remains byte-for-byte equivalent.
CREATE OR REPLACE FUNCTION automata_github_runtime_authority_v2_base_is_current(
    authority github_runtime_authority_issuances,
    observed_at BIGINT
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
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.run_id = run.id
         AND concrete.job_id = job.id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = run.id
         AND invocation.id = concrete.invocation_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = run.id
         AND logical_job.invocation_id = invocation.id
         AND logical_job.id = concrete.logical_job_id
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = logical_job.run_id
         AND preparation_claim.invocation_id = logical_job.invocation_id
         AND preparation_claim.logical_job_id = logical_job.id
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.run_id = preparation_claim.run_id
         AND preparation.invocation_id = preparation_claim.invocation_id
         AND preparation.logical_job_id = preparation_claim.logical_job_id
         AND preparation.descriptor_digest = preparation_claim.descriptor_digest
        JOIN workflow_plan_v2_activation_publications AS activation_publication
          ON activation_publication.run_id = logical_job.run_id
         AND activation_publication.invocation_id = logical_job.invocation_id
         AND activation_publication.logical_job_id = logical_job.id
         AND activation_publication.activation_input_digest =
             preparation.activation_input_digest
        JOIN workflow_plan_v2_instances AS instance
          ON instance.run_id = activation_publication.run_id
         AND instance.invocation_id = activation_publication.invocation_id
         AND instance.logical_job_id = activation_publication.logical_job_id
         AND instance.id = concrete.instance_id
        JOIN workflow_plan_v2_materialization_claims AS materialization
          ON materialization.instance_id = instance.id
         AND materialization.run_id = instance.run_id
         AND materialization.invocation_id = instance.invocation_id
         AND materialization.logical_job_id = instance.logical_job_id
        JOIN github_workflow_run_manifest_origins AS origin
          ON origin.tenant_id = repository.tenant_id
         AND origin.repository_id = repository.id
         AND origin.workflow_id = run.workflow_id
         AND origin.snapshot_id = run.snapshot_id
         AND origin.run_id = run.id
         AND origin.root_invocation_id = marker.root_invocation_id
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
         AND admission_receipt.github_subject_evidence_required
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
        LEFT JOIN github_server_service_authorities AS private_authority
          ON private_authority.tenant_id = origin.tenant_id
         AND private_authority.id = origin.private_source_authority_id
         AND private_authority.repository_id = origin.repository_id
         AND private_authority.provider_connection_id =
             origin.provider_connection_id
         AND private_authority.provider_installation_id =
             origin.provider_installation_id
         AND private_authority.github_repository_id = origin.github_repository_id
         AND private_authority.github_repository_name =
             origin.github_repository_name
         AND private_authority.service_scope = 'private_repository_source_read'
         AND private_authority.identity_digest =
             origin.private_source_authority_identity_digest
         AND private_authority.app_configuration_revision =
             origin.private_source_authority_app_configuration_revision
         AND private_authority.policy_revision =
             origin.private_source_authority_policy_revision
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
        WHERE attempt.id = authority.attempt_id
          AND attempt.job_id = authority.job_id
          AND attempt.fencing_token = authority.fencing_token
          AND attempt.lease_id = authority.lease_id
          AND attempt.lease_issued_at_ms = authority.lease_issued_at_ms
          AND attempt.lease_expires_at_ms = authority.lease_expires_at_ms
          AND attempt.lease_expires_at_ms > observed_at
          AND attempt.runner_id = authority.runner_id
          AND attempt.runner_session_id = authority.runner_session_id
          AND attempt.runner_session_epoch = authority.runner_session_epoch
          AND attempt.runner_generation = authority.runner_generation
          AND attempt.runner_slot = authority.runner_slot
          AND attempt.lifecycle IN ('leased', 'preparing', 'running')
          AND attempt.changed_at_ms <= observed_at
          AND job.admission_epoch = 4
          AND job.job_ir_schema = 5
          AND job.job_ir_schema = authority.job_ir_schema
          AND job.job_ir_size_bytes = authority.job_ir_size_bytes
          AND job.job_ir_digest = authority.job_ir_digest
          AND job.job_ir_digest = authority.policy_digest
          AND concrete.requirements = job.requirements
          AND concrete.instance_id = materialization.instance_id
          AND concrete.run_id = materialization.run_id
          AND concrete.invocation_id = materialization.invocation_id
          AND concrete.logical_job_id = materialization.logical_job_id
          AND concrete.descriptor_digest = materialization.descriptor_digest
          AND concrete.job_id = materialization.expected_job_id
          AND concrete.initial_attempt_id = materialization.expected_attempt_id
          AND concrete.claim_owner_id = materialization.owner_id
          AND concrete.claim_generation = materialization.generation
          AND concrete.claim_started_at_ms = materialization.claimed_at_ms
          AND concrete.claim_expires_at_ms = materialization.expires_at_ms
          AND concrete.committed_at_ms = materialization.updated_at_ms
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND (
              invocation.id <> marker.root_invocation_id
              OR run.plan_digest = invocation.plan_digest
          )
          AND run.plan_digest = origin.plan_digest
          AND run.event_digest = origin.event_digest
          AND run.head_sha = origin.github_check_head_sha
          AND run.event_name = origin.event_name
          AND run.git_ref = origin.git_ref
          AND run.status IN ('queued', 'in_progress')
          AND workflow.path = origin.workflow_path
          AND snapshot.source_digest = origin.source_digest
          AND marker.orchestration_schema = 1
          AND marker.admission_digest = origin.logical_admission_digest
          AND marker.admitted_at_ms = origin.admitted_at_ms
          AND marker.state IN ('pending', 'active')
          AND automata_workflow_plan_v2_invocation_published(
              run.id, invocation.id
          )
          AND invocation.plan_schema = 2
          AND (
              invocation.id <> marker.root_invocation_id
              OR invocation.plan_digest = origin.plan_digest
          )
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND logical_job.activation_input_digest =
              preparation.activation_input_digest
          AND preparation_claim.state = 'prepared'
          AND activation_publication.condition_matched
          AND activation_publication.job_ir_version = 5
          AND activation_publication.runtime_context_schema = 2
          AND instance.job_ir_version = 5
          AND instance.job_ir_digest = job.job_ir_digest
          AND instance.job_ir_size_bytes = job.job_ir_size_bytes
          AND instance.job_ir_object_key = job.job_ir_object_key
          AND instance.job_ir_media_type =
              'application/vnd.automata.job-ir.protobuf'
          AND materialization.state = 'materialized'
          AND concrete.runtime_context_schema = 2
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
          AND authority.provider_connection_id = origin.provider_connection_id
          AND authority.provider_connection_id = manifest.provider_connection_id
          AND authority.provider_installation_id =
              origin.provider_installation_id
          AND authority.provider_installation_id =
              manifest.provider_installation_id
          AND authority.github_repository_id = origin.github_repository_id
          AND authority.github_repository_id = manifest.github_repository_id
          AND authority.github_repository_name = origin.github_repository_name
          AND authority.github_repository_name = manifest.github_repository_name
          AND authority.authority_namespace = 'github.repository'
          AND authority.issuer_fingerprint = manifest.app_key_spki_sha256
          AND authority.configuration_fingerprint =
              checks_authority.configuration_fingerprint
          AND authority.requested_at_ms = attempt.lease_issued_at_ms
          AND authority.request_deadline_at_ms = LEAST(
              attempt.lease_expires_at_ms,
              attempt.lease_issued_at_ms + 120000
          )
          AND manifest.webhook_verifier_fingerprint_sha256 =
              origin.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              origin.authenticated_webhook_verifier_revision
          AND manifest.repository_visibility = origin.repository_visibility
          AND manifest.github_web_origin = 'https://github.com/'
          AND manifest.github_api_origin = 'https://api.github.com/'
          AND manifest.github_rest_api_version = '2026-03-10'
          AND manifest.github_app_id = checks_authority.github_app_id
          AND manifest.github_app_client_id = checks_authority.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind =
              checks_authority.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = checks_authority.app_key_spki_sha256
          AND manifest.app_configuration_revision =
              checks_authority.app_configuration_revision
          AND manifest.policy_revision = checks_authority.policy_revision
          AND manifest.registered_at_ms <= observed_at
          AND checks_authority.state = 'active'
          AND checks_authority.created_at_ms <= observed_at
          AND checks_authority.state_updated_at_ms <= observed_at
          AND origin.origin_kind IN (
              'provider_delivery', 'scheduled_fire', 'workflow_rerun'
          )
          AND (
              origin.repository_visibility = 'public'
              AND origin.private_source_authority_id IS NULL
              AND private_authority.id IS NULL
              OR origin.repository_visibility = 'private'
              AND private_authority.id IS NOT NULL
              AND private_authority.github_app_id = manifest.github_app_id
              AND private_authority.github_app_client_id =
                  manifest.github_app_client_id
              AND private_authority.github_app_jwt_issuer_kind =
                  manifest.github_app_jwt_issuer_kind
              AND private_authority.app_key_spki_sha256 =
                  manifest.app_key_spki_sha256
              AND private_authority.app_configuration_revision =
                  manifest.app_configuration_revision
              AND private_authority.policy_revision = manifest.policy_revision
              AND private_authority.state = 'active'
              AND private_authority.created_at_ms <= observed_at
              AND private_authority.state_updated_at_ms <= observed_at
          )
          AND origin.admitted_at_ms <= observed_at
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND session.job_ir_schema = 5
          AND session.disconnected_at_ms IS NULL
    )
$automata$;

-- 0044's v3 provenance closure used the delivery table directly. Carry the
-- same exact manifest/runtime-policy/selection evidence through the closed
-- origin projection so public scheduled jobs and reusable children share one
-- currentness model without fabricating provider-delivery identity.
CREATE OR REPLACE FUNCTION automata_github_runtime_authority_has_v3_provenance(
    authority github_runtime_authority_issuances
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
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
        LEFT JOIN github_server_service_authorities AS private_authority
          ON private_authority.tenant_id = origin.tenant_id
         AND private_authority.id = origin.private_source_authority_id
         AND private_authority.repository_id = origin.repository_id
         AND private_authority.provider_connection_id =
             origin.provider_connection_id
         AND private_authority.provider_installation_id =
             origin.provider_installation_id
         AND private_authority.github_repository_id = origin.github_repository_id
         AND private_authority.github_repository_name =
             origin.github_repository_name
         AND private_authority.service_scope = 'private_repository_source_read'
         AND private_authority.identity_digest =
             origin.private_source_authority_identity_digest
         AND private_authority.app_configuration_revision =
             origin.private_source_authority_app_configuration_revision
         AND private_authority.policy_revision =
             origin.private_source_authority_policy_revision
        JOIN workflow_admission_receipts AS admission
          ON admission.tenant_id = origin.tenant_id
         AND admission.idempotency_kind = origin.admission_idempotency_kind
         AND admission.idempotency_key = origin.admission_idempotency_key
         AND admission.request_digest = origin.logical_admission_digest
         AND admission.repository_id = origin.repository_id
         AND admission.run_id = origin.run_id
         AND admission.committed_at_ms = origin.admitted_at_ms
         AND admission.github_subject_evidence_required
        JOIN workflow_plan_v2_runtime_policy_pins AS pin
          ON pin.run_id = origin.run_id
         AND pin.tenant_id = origin.tenant_id
         AND pin.repository_id = origin.repository_id
        JOIN workflow_runtime_policy_revisions AS policy
          ON policy.tenant_id = pin.tenant_id
         AND policy.repository_id = pin.repository_id
         AND policy.policy_revision = pin.policy_revision
         AND policy.policy_digest = pin.policy_digest
         AND policy.state = 'sealed'
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.job_id = authority.job_id
         AND concrete.run_id = authority.run_id
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
        JOIN workflow_plan_v2_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN workflow_plan_v2_activation_publications AS activation_publication
          ON activation_publication.run_id = instance.run_id
         AND activation_publication.invocation_id = instance.invocation_id
         AND activation_publication.logical_job_id = instance.logical_job_id
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.run_id = activation_publication.run_id
         AND preparation.invocation_id = activation_publication.invocation_id
         AND preparation.logical_job_id = activation_publication.logical_job_id
         AND preparation.activation_input_digest =
             activation_publication.activation_input_digest
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = preparation.run_id
         AND preparation_claim.invocation_id = preparation.invocation_id
         AND preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.descriptor_digest = preparation.descriptor_digest
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = concrete.run_id
         AND invocation.id = concrete.invocation_id
        JOIN workflow_plan_v2_runs AS marker
          ON marker.run_id = concrete.run_id
        WHERE origin.tenant_id = authority.tenant_id
          AND origin.repository_id = authority.repository_id
          AND origin.run_id = authority.run_id
          AND origin.origin_kind IN (
              'provider_delivery', 'scheduled_fire', 'workflow_rerun'
          )
          AND (
              origin.repository_visibility = 'public'
              AND origin.private_source_authority_id IS NULL
              AND private_authority.id IS NULL
              OR origin.repository_visibility = 'private'
              AND private_authority.id IS NOT NULL
              AND private_authority.github_app_id = manifest.github_app_id
              AND private_authority.github_app_client_id =
                  manifest.github_app_client_id
              AND private_authority.github_app_jwt_issuer_kind =
                  manifest.github_app_jwt_issuer_kind
              AND private_authority.app_key_spki_sha256 =
                  manifest.app_key_spki_sha256
              AND private_authority.app_configuration_revision =
                  manifest.app_configuration_revision
              AND private_authority.policy_revision = manifest.policy_revision
          )
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
          AND automata_workflow_plan_v2_invocation_published(
              concrete.run_id, concrete.invocation_id
          )
          AND invocation.plan_schema = 2
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
$automata$;

-- The insert/update identity guard from 0044 must use the same closed run
-- origin and sealed-invocation predicate as currentness. A scheduled fire is
-- not a provider delivery, and a reusable child is not the root invocation;
-- neither distinction may be erased by manufacturing legacy evidence.
CREATE OR REPLACE FUNCTION automata_validate_github_runtime_authority_v3_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM job_attempts AS attempt
    JOIN jobs AS job
      ON job.id = attempt.job_id
     AND job.id = NEW.job_id
     AND job.run_id = NEW.run_id
    JOIN workflow_runs AS run
      ON run.id = job.run_id
     AND run.repository_id = NEW.repository_id
    JOIN repositories AS repository
      ON repository.id = run.repository_id
     AND repository.tenant_id = NEW.tenant_id
    JOIN workflow_definitions AS workflow
      ON workflow.id = run.workflow_id
     AND workflow.repository_id = run.repository_id
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
    JOIN workflow_plan_v2_concrete_jobs AS concrete
      ON concrete.run_id = run.id
     AND concrete.job_id = job.id
    JOIN workflow_plan_v2_invocations AS invocation
      ON invocation.run_id = concrete.run_id
     AND invocation.id = concrete.invocation_id
    JOIN workflow_plan_v2_runs AS marker
      ON marker.run_id = concrete.run_id
    JOIN runners AS runner
      ON runner.id = NEW.runner_id
     AND runner.tenant_id = repository.tenant_id
    JOIN runner_sessions AS session
      ON session.id = NEW.runner_session_id
     AND session.runner_id = runner.id
    WHERE attempt.id = NEW.attempt_id
      AND attempt.job_id = NEW.job_id
      AND job.job_ir_schema = NEW.job_ir_schema
      AND job.job_ir_size_bytes = NEW.job_ir_size_bytes
      AND job.job_ir_digest = NEW.job_ir_digest
      AND job.job_ir_digest = NEW.policy_digest
      AND repository.scm_provider = 'github'
      AND repository.provider_repository_id = NEW.github_repository_id::TEXT
      AND repository.owner || '/' || repository.name = NEW.github_repository_name
      AND runner.id = NEW.runner_id
      AND session.id = NEW.runner_session_id
      AND session.session_epoch = NEW.runner_session_epoch
      AND session.runner_generation = NEW.runner_generation
      AND invocation.plan_schema = 2
      AND automata_workflow_plan_v2_invocation_published(
          run.id, invocation.id
      )
    FOR SHARE OF attempt, job, run, repository, workflow, snapshot, concrete,
                 invocation, marker, runner, session;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub runtime authority lacks exact execution provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_v3_execution_provenance';
    END IF;

    IF NOT automata_github_runtime_authority_has_v3_provenance(NEW) THEN
        RAISE EXCEPTION 'GitHub runtime authority lacks exact historical policy provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_v3_historical_provenance';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_default_public_run_id_alias
BEFORE INSERT ON workflow_runs
FOR EACH ROW EXECUTE FUNCTION automata_default_workflow_public_run_id_alias();

-- Every pre-rerun physical row is its own provider-visible first attempt.
UPDATE workflow_runs
SET public_run_id_alias = run_id_alias
WHERE public_run_id_alias IS NULL;

ALTER TABLE workflow_runs
    ALTER COLUMN public_run_id_alias SET NOT NULL;

CREATE UNIQUE INDEX workflow_runs_public_id_attempt
    ON workflow_runs (workflow_id, public_run_id_alias, run_attempt);

CREATE FUNCTION automata_reject_workflow_run_rerun_identity_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.public_run_id_alias IS DISTINCT FROM OLD.public_run_id_alias
       OR NEW.triggering_actor IS DISTINCT FROM OLD.triggering_actor
       OR NEW.concurrency_cancel_in_progress IS DISTINCT FROM
          OLD.concurrency_cancel_in_progress
    THEN
        RAISE EXCEPTION 'workflow rerun identity is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_runs_rerun_identity_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_rerun_identity_immutable
BEFORE UPDATE OF public_run_id_alias, triggering_actor,
                 concurrency_cancel_in_progress ON workflow_runs
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_run_rerun_identity_mutation();

-- The first row for a group is lazily recorded when it is first rerun.  This
-- avoids backfilling or changing historical runs while making every later
-- physical attempt point at the same attempt-one root.
CREATE TABLE workflow_rerun_attempts (
    run_id UUID PRIMARY KEY
        REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    root_run_id UUID NOT NULL
        REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    source_run_id UUID
        REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    attempt INTEGER NOT NULL,
    source_admission_digest BYTEA NOT NULL,
    source_plan_digest BYTEA NOT NULL,
    source_event_digest BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_rerun_attempts_ids_non_nil CHECK (
        run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND root_run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (source_run_id IS NULL OR source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid)
    ),
    CONSTRAINT workflow_rerun_attempts_root_shape CHECK (
        (source_run_id IS NULL AND run_id = root_run_id AND attempt = 1)
        OR (source_run_id IS NOT NULL AND run_id <> root_run_id AND attempt BETWEEN 2 AND 51)
    ),
    CONSTRAINT workflow_rerun_attempts_digest_shape CHECK (
        octet_length(source_admission_digest) = 32
        AND octet_length(source_plan_digest) = 32
        AND octet_length(source_event_digest) = 32
    ),
    CONSTRAINT workflow_rerun_attempts_time CHECK (created_at_ms >= 0),
    CONSTRAINT workflow_rerun_attempts_run_source_unique UNIQUE (run_id, source_run_id),
    CONSTRAINT workflow_rerun_attempts_root_attempt_unique UNIQUE (root_run_id, attempt)
);

CREATE INDEX workflow_rerun_attempts_source ON workflow_rerun_attempts (source_run_id)
    WHERE source_run_id IS NOT NULL;

CREATE FUNCTION automata_reject_workflow_rerun_attempt_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun attempt evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_attempts_immutable';
END;
$automata$;

CREATE TRIGGER workflow_rerun_attempts_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_attempts
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_attempt_mutation();

CREATE TRIGGER workflow_rerun_attempts_no_truncate
BEFORE TRUNCATE ON workflow_rerun_attempts
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_rerun_attempt_mutation();

CREATE FUNCTION automata_validate_workflow_rerun_attempt_lineage()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS run
        JOIN workflow_runs AS root ON root.id = NEW.root_run_id
        JOIN workflow_runs AS source_run
          ON source_run.id = COALESCE(NEW.source_run_id, NEW.run_id)
        JOIN workflow_plan_v2_runs AS source_marker
          ON source_marker.run_id = source_run.id
        LEFT JOIN workflow_rerun_attempts AS source
          ON source.run_id = NEW.source_run_id
        WHERE run.id = NEW.run_id
          AND run.run_attempt = NEW.attempt
          AND run.created_at_ms = NEW.created_at_ms
          AND run.workflow_id = root.workflow_id
          AND run.public_run_id_alias = root.public_run_id_alias
          AND run.run_number = root.run_number
          AND root.run_attempt = 1
          AND run.repository_id = source_run.repository_id
          AND source_run.workflow_id = root.workflow_id
          AND source_run.public_run_id_alias = root.public_run_id_alias
          AND run.snapshot_id = source_run.snapshot_id
          AND run.run_number = source_run.run_number
          AND run.event_name = source_run.event_name
          AND run.event_object_key = source_run.event_object_key
          AND run.head_sha = source_run.head_sha
          AND run.concurrency_group_key IS NOT DISTINCT FROM
              source_run.concurrency_group_key
          AND run.concurrency_queue_policy IS NOT DISTINCT FROM
              source_run.concurrency_queue_policy
          AND run.concurrency_cancel_in_progress IS NOT DISTINCT FROM
              source_run.concurrency_cancel_in_progress
          AND (
              run.concurrency_group_key IS NULL
              AND run.concurrency_queue_policy IS NULL
              AND run.concurrency_cancel_in_progress IS NULL
              OR run.concurrency_group_key IS NOT NULL
              AND run.concurrency_queue_policy IS NOT NULL
              AND run.concurrency_cancel_in_progress IS NOT NULL
          )
          AND run.admission_epoch = source_run.admission_epoch
          AND run.event_digest = source_run.event_digest
          AND run.event_size_bytes = source_run.event_size_bytes
          AND run.event_media_type = source_run.event_media_type
          AND run.plan_digest = source_run.plan_digest
          AND run.plan_object_key = source_run.plan_object_key
          AND run.plan_size_bytes = source_run.plan_size_bytes
          AND run.plan_media_type = source_run.plan_media_type
          AND run.plan_schema = source_run.plan_schema
          AND run.workflow_name IS NOT DISTINCT FROM source_run.workflow_name
          AND run.git_ref IS NOT DISTINCT FROM source_run.git_ref
          AND run.actor IS NOT DISTINCT FROM source_run.actor
          AND run.display_title IS NOT DISTINCT FROM source_run.display_title
          AND run.commit_subject IS NOT DISTINCT FROM source_run.commit_subject
          AND run.publication_policy_revision IS NOT DISTINCT FROM
              source_run.publication_policy_revision
          AND run.requested_dashboard_visibility IS NOT DISTINCT FROM
              source_run.requested_dashboard_visibility
          AND run.effective_dashboard_visibility IS NOT DISTINCT FROM
              source_run.effective_dashboard_visibility
          AND run.requested_log_visibility IS NOT DISTINCT FROM
              source_run.requested_log_visibility
          AND run.requested_artifact_visibility IS NOT DISTINCT FROM
              source_run.requested_artifact_visibility
          AND run.publication_safety_reason IS NOT DISTINCT FROM
              source_run.publication_safety_reason
          AND run.publication_safety_schema IS NOT DISTINCT FROM
              source_run.publication_safety_schema
          AND source_marker.admission_digest = NEW.source_admission_digest
          AND source_run.plan_digest = NEW.source_plan_digest
          AND source_run.event_digest = NEW.source_event_digest
          AND (
              NEW.attempt = 1
              AND NEW.run_id = NEW.root_run_id
              AND NEW.source_run_id IS NULL
              OR NEW.attempt > 1
              AND NEW.run_id <> NEW.root_run_id
              AND NEW.source_run_id IS NOT NULL
              AND source.root_run_id = NEW.root_run_id
              AND source.attempt < NEW.attempt
          )
    ) OR EXISTS (
        SELECT 1
        FROM generate_series(1, NEW.attempt) AS expected(attempt)
        WHERE NOT EXISTS (
            SELECT 1
            FROM workflow_rerun_attempts AS durable
            WHERE durable.root_run_id = NEW.root_run_id
              AND durable.attempt = expected.attempt
        )
    ) THEN
        RAISE EXCEPTION 'workflow rerun attempt lineage is not contiguous and exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_attempts_lineage_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_rerun_attempts_validate_lineage
AFTER INSERT ON workflow_rerun_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_rerun_attempt_lineage();

CREATE FUNCTION automata_validate_workflow_run_public_rerun_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    candidate workflow_runs%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'workflow_runs' THEN
        candidate := NEW;
    ELSE
        SELECT * INTO candidate FROM workflow_runs WHERE id = NEW.run_id;
    END IF;
    IF candidate.id IS NULL THEN
        RAISE EXCEPTION 'workflow rerun public identity has no physical run'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_run_public_rerun_identity_exact';
    ELSIF candidate.public_run_id_alias = candidate.run_id_alias THEN
        IF EXISTS (
            SELECT 1 FROM workflow_rerun_attempts AS attempt
            WHERE attempt.run_id = candidate.id
              AND attempt.source_run_id IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'workflow run root public identity is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'workflow_run_public_rerun_identity_exact';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_runs AS root ON root.id = attempt.root_run_id
        WHERE attempt.run_id = candidate.id
          AND attempt.source_run_id IS NOT NULL
          AND attempt.attempt = candidate.run_attempt
          AND root.run_attempt = 1
          AND root.run_id_alias = root.public_run_id_alias
          AND root.public_run_id_alias = candidate.public_run_id_alias
          AND root.workflow_id = candidate.workflow_id
          AND root.run_number = candidate.run_number
    ) THEN
        RAISE EXCEPTION 'workflow run public identity lacks exact rerun lineage'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_run_public_rerun_identity_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_runs_validate_public_rerun_identity
AFTER INSERT ON workflow_runs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_run_public_rerun_identity();

CREATE CONSTRAINT TRIGGER workflow_rerun_attempts_validate_public_identity
AFTER INSERT ON workflow_rerun_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_run_public_rerun_identity();

-- Human rerun requests are their own operation-idempotency and audit boundary.
CREATE TABLE workflow_rerun_requests (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    operation_id UUID NOT NULL,
    request_digest BYTEA NOT NULL,
    repository_id UUID NOT NULL,
    source_run_id UUID NOT NULL,
    selection_kind TEXT NOT NULL,
    selected_source_job_id UUID,
    actor_principal_id UUID NOT NULL,
    actor_session_id UUID NOT NULL,
    authorization_revision BIGINT NOT NULL,
    rerun_run_id UUID,
    committed_at_ms BIGINT,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT workflow_rerun_requests_tenant_run_unique
        UNIQUE (tenant_id, rerun_run_id),
    CONSTRAINT workflow_rerun_requests_operation_run_unique
        UNIQUE (tenant_id, operation_id, rerun_run_id),
    CONSTRAINT workflow_rerun_requests_ids_non_nil CHECK (
        operation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND actor_principal_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND actor_session_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (rerun_run_id IS NULL OR rerun_run_id <> '00000000-0000-0000-0000-000000000000'::uuid)
    ),
    CONSTRAINT workflow_rerun_requests_digest_shape CHECK (octet_length(request_digest) = 32),
    CONSTRAINT workflow_rerun_requests_selection_shape CHECK (
        (selection_kind IN ('entire_workflow', 'failed_jobs_and_dependents')
         AND selected_source_job_id IS NULL)
        OR (selection_kind = 'job_and_dependents'
            AND selected_source_job_id IS NOT NULL)
    ),
    CONSTRAINT workflow_rerun_requests_revision_positive CHECK (authorization_revision > 0),
    CONSTRAINT workflow_rerun_requests_completion_shape CHECK (
        (rerun_run_id IS NULL AND committed_at_ms IS NULL)
        OR (rerun_run_id IS NOT NULL AND committed_at_ms IS NOT NULL AND committed_at_ms >= 0)
    ),
    CONSTRAINT workflow_rerun_requests_actor_membership_fk FOREIGN KEY (
        tenant_id, actor_principal_id
    ) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_actor_session_fk FOREIGN KEY (
        tenant_id, actor_principal_id, actor_session_id
    ) REFERENCES human_sessions(tenant_id, principal_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_repository_fk FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_source_fk FOREIGN KEY (repository_id, source_run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_rerun_fk FOREIGN KEY (repository_id, rerun_run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_selected_job_fk FOREIGN KEY (selected_source_job_id)
        REFERENCES workflow_plan_v2_jobs(id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_selected_source_job_fk FOREIGN KEY (
        source_run_id, selected_source_job_id
    ) REFERENCES workflow_plan_v2_run_result_jobs(run_id, logical_job_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_attempt_source_fk FOREIGN KEY (
        rerun_run_id, source_run_id
    ) REFERENCES workflow_rerun_attempts(run_id, source_run_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE FUNCTION automata_validate_workflow_rerun_request_complete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    admitted_at BIGINT;
    root_created_at BIGINT;
    actor_exact BOOLEAN;
    mapped_snapshot_id UUID;
    mapped_organization_id BIGINT;
    mapped_team_id BIGINT;
BEGIN
    IF NEW.rerun_run_id IS NULL OR NEW.committed_at_ms IS NULL THEN
        RAISE EXCEPTION 'workflow rerun requests must commit complete'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_rerun_requests_completion_exact';
    END IF;
    SELECT attempt.created_at_ms, root.created_at_ms
      INTO admitted_at, root_created_at
    FROM workflow_rerun_attempts AS attempt
    JOIN workflow_runs AS root ON root.id = attempt.root_run_id
    WHERE attempt.run_id = NEW.rerun_run_id
      AND attempt.source_run_id = NEW.source_run_id;
    IF NOT FOUND
        OR root_created_at > admitted_at
        OR admitted_at - root_created_at > 2592000000
        OR automata_workflow_rerun_now_ms() - root_created_at > 2592000000
        OR admitted_at <> automata_workflow_rerun_now_ms()
    THEN
        RAISE EXCEPTION 'workflow rerun request age is not exact'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_rerun_requests_age_exact';
    END IF;

    SELECT TRUE INTO actor_exact
    FROM human_sessions AS session
    JOIN human_principals AS principal
      ON principal.id = session.principal_id
    JOIN tenant_human_memberships AS membership
      ON membership.tenant_id = session.tenant_id
     AND membership.principal_id = session.principal_id
    WHERE session.tenant_id = NEW.tenant_id
      AND session.principal_id = NEW.actor_principal_id
      AND session.id = NEW.actor_session_id
      AND principal.status = 'active'
      AND membership.status = 'active'
      AND membership.authorization_revision = NEW.authorization_revision
      AND session.authorization_revision = NEW.authorization_revision
      AND session.revoked_at_ms IS NULL
      AND session.issued_at_ms <= admitted_at
      AND session.idle_expires_at_ms > admitted_at
      AND session.expires_at_ms > admitted_at
      AND (
          session.session_kind = 'browser'
          AND session.audience = 'automata.web'
          OR session.session_kind = 'cli'
          AND session.audience = 'automata.cli'
      )
      AND EXISTS (
          SELECT 1
          FROM rbac_role_bindings AS binding
          JOIN rbac_role_permissions AS permission
            ON permission.tenant_id = binding.tenant_id
           AND permission.role_id = binding.role_id
          WHERE binding.tenant_id = NEW.tenant_id
            AND binding.principal_id = NEW.actor_principal_id
            AND binding.status = 'active'
            AND (
                binding.valid_until_ms IS NULL
                OR binding.valid_until_ms > admitted_at
            )
            AND permission.permission_name = 'runs:rerun'
            AND (
                binding.scope_kind = 'tenant'
                AND binding.repository_id IS NULL
                AND binding.runner_group_id IS NULL
                OR binding.scope_kind = 'repository'
                AND binding.repository_id = NEW.repository_id
                AND binding.runner_group_id IS NULL
            )
          UNION ALL
          SELECT 1
          FROM github_membership_snapshots AS snapshot
          JOIN human_provider_identities AS identity
            ON identity.principal_id = snapshot.principal_id
           AND identity.provider_id = snapshot.provider_id
           AND identity.provider_subject = snapshot.provider_subject
          JOIN human_provider_tokens AS provider_token
            ON provider_token.tenant_id = snapshot.tenant_id
           AND provider_token.principal_id = snapshot.principal_id
           AND provider_token.provider_id = snapshot.provider_id
           AND provider_token.provider_subject = snapshot.provider_subject
           AND provider_token.version = snapshot.provider_token_version
          JOIN github_role_mappings AS mapping
            ON mapping.tenant_id = snapshot.tenant_id
           AND mapping.provider_id = snapshot.provider_id
           AND mapping.status = 'active'
          JOIN rbac_role_permissions AS mapped_permission
            ON mapped_permission.tenant_id = mapping.tenant_id
           AND mapped_permission.role_id = mapping.role_id
          WHERE snapshot.tenant_id = NEW.tenant_id
            AND snapshot.principal_id = NEW.actor_principal_id
            AND snapshot.provider_id = 'github'
            AND snapshot.provider_id = session.provider_id
            AND snapshot.provider_subject = session.provider_subject
            AND snapshot.observed_at_ms <= admitted_at
            AND snapshot.valid_until_ms > admitted_at
            AND provider_token.revoked_at_ms IS NULL
            AND provider_token.issued_at_ms <= snapshot.observed_at_ms
            AND (
                provider_token.access_expires_at_ms IS NULL
                OR provider_token.access_expires_at_ms > admitted_at
                AND snapshot.valid_until_ms <=
                    provider_token.access_expires_at_ms
            )
            AND mapped_permission.permission_name = 'runs:rerun'
            AND (
                mapping.scope_kind = 'tenant'
                AND mapping.repository_id IS NULL
                AND mapping.runner_group_id IS NULL
                OR mapping.scope_kind = 'repository'
                AND mapping.repository_id = NEW.repository_id
                AND mapping.runner_group_id IS NULL
            )
            AND (
                mapping.team_id IS NULL
                AND EXISTS (
                    SELECT 1
                    FROM github_organization_membership_observations AS organization
                    WHERE organization.tenant_id = snapshot.tenant_id
                      AND organization.snapshot_id = snapshot.id
                      AND organization.organization_id =
                          mapping.organization_id
                )
                OR mapping.team_id IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM github_team_membership_observations AS team
                    WHERE team.tenant_id = snapshot.tenant_id
                      AND team.snapshot_id = snapshot.id
                      AND team.organization_id = mapping.organization_id
                      AND team.team_id = mapping.team_id
                )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM github_membership_snapshots AS newer
                WHERE newer.tenant_id = snapshot.tenant_id
                  AND newer.principal_id = snapshot.principal_id
                  AND newer.provider_id = snapshot.provider_id
                  AND newer.provider_subject = snapshot.provider_subject
                  AND newer.observed_at_ms <= admitted_at
                  AND (
                      newer.observed_at_ms > snapshot.observed_at_ms
                      OR newer.observed_at_ms = snapshot.observed_at_ms
                      AND newer.id <> snapshot.id
                  )
            )
      )
    FOR SHARE OF session, principal, membership;
    IF actor_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow rerun request actor is not currently authorized'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_rerun_requests_authority_exact';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM rbac_role_bindings AS binding
        JOIN rbac_role_permissions AS permission
          ON permission.tenant_id = binding.tenant_id
         AND permission.role_id = binding.role_id
        WHERE binding.tenant_id = NEW.tenant_id
          AND binding.principal_id = NEW.actor_principal_id
          AND binding.status = 'active'
          AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > admitted_at)
          AND permission.permission_name = 'runs:rerun'
          AND (
              binding.scope_kind = 'tenant'
              AND binding.repository_id IS NULL
              AND binding.runner_group_id IS NULL
              OR binding.scope_kind = 'repository'
              AND binding.repository_id = NEW.repository_id
              AND binding.runner_group_id IS NULL
          )
    ) THEN
        SELECT snapshot.id, mapping.organization_id, mapping.team_id
          INTO mapped_snapshot_id, mapped_organization_id, mapped_team_id
        FROM github_membership_snapshots AS snapshot
        JOIN human_provider_identities AS identity
          ON identity.principal_id = snapshot.principal_id
         AND identity.provider_id = snapshot.provider_id
         AND identity.provider_subject = snapshot.provider_subject
        JOIN human_provider_tokens AS provider_token
          ON provider_token.tenant_id = snapshot.tenant_id
         AND provider_token.principal_id = snapshot.principal_id
         AND provider_token.provider_id = snapshot.provider_id
         AND provider_token.provider_subject = snapshot.provider_subject
         AND provider_token.version = snapshot.provider_token_version
        JOIN github_role_mappings AS mapping
          ON mapping.tenant_id = snapshot.tenant_id
         AND mapping.provider_id = snapshot.provider_id
         AND mapping.status = 'active'
        JOIN rbac_role_permissions AS mapped_permission
          ON mapped_permission.tenant_id = mapping.tenant_id
         AND mapped_permission.role_id = mapping.role_id
        WHERE snapshot.tenant_id = NEW.tenant_id
          AND snapshot.principal_id = NEW.actor_principal_id
          AND snapshot.provider_id = 'github'
          AND snapshot.provider_id = (
              SELECT session.provider_id FROM human_sessions AS session
              WHERE session.tenant_id = NEW.tenant_id
                AND session.principal_id = NEW.actor_principal_id
                AND session.id = NEW.actor_session_id
          )
          AND snapshot.provider_subject = (
              SELECT session.provider_subject FROM human_sessions AS session
              WHERE session.tenant_id = NEW.tenant_id
                AND session.principal_id = NEW.actor_principal_id
                AND session.id = NEW.actor_session_id
          )
          AND snapshot.provider_subject ~ '^[1-9][0-9]*$'
          AND length(snapshot.provider_subject) <= 20
          AND snapshot.provider_subject::NUMERIC <= 18446744073709551615
          AND snapshot.observed_at_ms <= admitted_at
          AND snapshot.valid_until_ms > admitted_at
          AND provider_token.revoked_at_ms IS NULL
          AND provider_token.issued_at_ms <= snapshot.observed_at_ms
          AND (
              provider_token.access_expires_at_ms IS NULL
              OR provider_token.access_expires_at_ms > admitted_at
              AND snapshot.valid_until_ms <= provider_token.access_expires_at_ms
          )
          AND mapped_permission.permission_name = 'runs:rerun'
          AND (
              mapping.scope_kind = 'tenant'
              AND mapping.repository_id IS NULL
              AND mapping.runner_group_id IS NULL
              OR mapping.scope_kind = 'repository'
              AND mapping.repository_id = NEW.repository_id
              AND mapping.runner_group_id IS NULL
          )
          AND (
              mapping.team_id IS NULL
              AND
              EXISTS (
                  SELECT 1
                  FROM github_organization_membership_observations AS organization
                  WHERE organization.tenant_id = snapshot.tenant_id
                    AND organization.snapshot_id = snapshot.id
                    AND organization.organization_id = mapping.organization_id
              )
              OR mapping.team_id IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM github_team_membership_observations AS team
                  WHERE team.tenant_id = snapshot.tenant_id
                    AND team.snapshot_id = snapshot.id
                    AND team.organization_id = mapping.organization_id
                    AND team.team_id = mapping.team_id
              )
          )
          AND NOT EXISTS (
              SELECT 1 FROM github_membership_snapshots AS newer
              WHERE newer.tenant_id = snapshot.tenant_id
                AND newer.principal_id = snapshot.principal_id
                AND newer.provider_id = snapshot.provider_id
                AND newer.provider_subject = snapshot.provider_subject
                AND newer.observed_at_ms <= admitted_at
                AND (
                    newer.observed_at_ms > snapshot.observed_at_ms
                    OR newer.observed_at_ms = snapshot.observed_at_ms
                    AND newer.id <> snapshot.id
                )
          )
        ORDER BY snapshot.observed_at_ms DESC, snapshot.id DESC
        LIMIT 1
        FOR SHARE OF snapshot, identity, provider_token, mapping,
                     mapped_permission;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'workflow rerun mapped actor evidence is not exact'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'workflow_rerun_requests_authority_exact';
        END IF;
        IF mapped_team_id IS NULL THEN
            PERFORM 1
            FROM github_organization_membership_observations AS organization
            WHERE organization.tenant_id = NEW.tenant_id
              AND organization.snapshot_id = mapped_snapshot_id
              AND organization.organization_id = mapped_organization_id
            FOR SHARE OF organization;
        ELSE
            PERFORM 1
            FROM github_organization_membership_observations AS organization
            JOIN github_team_membership_observations AS team
              ON team.tenant_id = organization.tenant_id
             AND team.snapshot_id = organization.snapshot_id
             AND team.organization_id = organization.organization_id
            WHERE organization.tenant_id = NEW.tenant_id
              AND organization.snapshot_id = mapped_snapshot_id
              AND organization.organization_id = mapped_organization_id
              AND team.team_id = mapped_team_id
            FOR SHARE OF organization, team;
        END IF;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'workflow rerun mapped membership evidence is not exact'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'workflow_rerun_requests_authority_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_rerun_requests_validate_completion
AFTER INSERT ON workflow_rerun_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_rerun_request_complete();

CREATE FUNCTION automata_reject_workflow_rerun_request_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun request evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_requests_immutable';
END;
$automata$;

CREATE TRIGGER workflow_rerun_requests_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_requests
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_request_mutation();

CREATE TRIGGER workflow_rerun_requests_no_truncate
BEFORE TRUNCATE ON workflow_rerun_requests
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_rerun_request_mutation();

-- A committed rerun has exactly one append-only audit event whose actor,
-- target, request digest, and database timestamp match the admission ledger.
CREATE UNIQUE INDEX security_audit_events_workflow_rerun_target
    ON security_audit_events (tenant_id, resource_id)
    WHERE action = 'workflow.rerun'
      AND resource_kind = 'workflow_run';

CREATE TABLE workflow_rerun_audit_evidence (
    run_id UUID PRIMARY KEY
        REFERENCES workflow_rerun_attempts(run_id) ON DELETE RESTRICT,
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    event_id UUID NOT NULL UNIQUE
        REFERENCES security_audit_events(event_id) ON DELETE RESTRICT,
    request_digest BYTEA NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_rerun_audit_evidence_request FOREIGN KEY (
        tenant_id, operation_id, run_id
    ) REFERENCES workflow_rerun_requests(
        tenant_id, operation_id, rerun_run_id
    ) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_audit_evidence_shape CHECK (
        run_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND operation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND event_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND octet_length(request_digest) = 32
        AND recorded_at_ms >= 0
    )
);

CREATE FUNCTION automata_validate_workflow_rerun_audit_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.tenant_id = NEW.tenant_id
         AND request.operation_id = NEW.operation_id
         AND request.rerun_run_id = attempt.run_id
         AND request.source_run_id = attempt.source_run_id
        JOIN security_audit_events AS audit
          ON audit.event_id = NEW.event_id
         AND audit.tenant_id = request.tenant_id
        WHERE attempt.run_id = NEW.run_id
          AND attempt.source_run_id IS NOT NULL
          AND request.request_digest = NEW.request_digest
          AND request.committed_at_ms = attempt.created_at_ms
          AND NEW.recorded_at_ms = attempt.created_at_ms
          AND audit.occurred_at_ms = attempt.created_at_ms
          AND audit.actor_kind = 'human'
          AND audit.actor_principal_id = request.actor_principal_id
          AND audit.actor_session_id = request.actor_session_id
          AND audit.authorization_revision = request.authorization_revision
          AND audit.action = 'workflow.rerun'
          AND audit.outcome = 'succeeded'
          AND audit.resource_kind = 'workflow_run'
          AND audit.resource_id = attempt.run_id::TEXT
    ) THEN
        RAISE EXCEPTION 'workflow rerun audit evidence is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_audit_evidence_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_rerun_audit_evidence_insert_guard
BEFORE INSERT ON workflow_rerun_audit_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_rerun_audit_evidence();

CREATE FUNCTION automata_reject_workflow_rerun_audit_evidence_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun audit evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workflow_rerun_audit_evidence_immutable';
END;
$automata$;

CREATE TRIGGER workflow_rerun_audit_evidence_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_audit_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_rerun_audit_evidence_mutation();

CREATE TRIGGER workflow_rerun_audit_evidence_no_truncate
BEFORE TRUNCATE ON workflow_rerun_audit_evidence
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_rerun_audit_evidence_mutation();

CREATE FUNCTION automata_require_workflow_rerun_audit_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    candidate_run_id UUID;
BEGIN
    candidate_run_id := NEW.run_id;
    IF EXISTS (
        SELECT 1
        FROM workflow_rerun_attempts AS attempt
        WHERE attempt.run_id = candidate_run_id
          AND attempt.source_run_id IS NOT NULL
    ) AND NOT EXISTS (
        SELECT 1
        FROM workflow_rerun_audit_evidence AS evidence
        WHERE evidence.run_id = candidate_run_id
    ) THEN
        RAISE EXCEPTION 'workflow rerun requires atomic audit evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_audit_evidence_required';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_rerun_attempts_require_audit_evidence
AFTER INSERT ON workflow_rerun_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_workflow_rerun_audit_evidence();

CREATE CONSTRAINT TRIGGER workflow_rerun_audit_evidence_require_exact
AFTER INSERT ON workflow_rerun_audit_evidence
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_workflow_rerun_audit_evidence();

CREATE FUNCTION automata_validate_workflow_rerun_concurrency_slot()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    candidate_run_id UUID;
    exact_slot_count BIGINT;
    all_slot_count BIGINT;
    concurrency_key TEXT;
    repository UUID;
    admitted_at BIGINT;
BEGIN
    candidate_run_id := NEW.run_id;
    SELECT run.repository_id, run.concurrency_group_key, attempt.created_at_ms
      INTO repository, concurrency_key, admitted_at
    FROM workflow_rerun_attempts AS attempt
    JOIN workflow_runs AS run ON run.id = attempt.run_id
    WHERE attempt.run_id = candidate_run_id
      AND attempt.source_run_id IS NOT NULL;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*) INTO all_slot_count
    FROM (
        SELECT concurrency.repository_id, concurrency.normalized_key,
               concurrency.running_run_id AS run_id,
               concurrency.updated_at_ms AS slot_at_ms
        FROM concurrency_groups AS concurrency
        WHERE concurrency.running_run_id = candidate_run_id
        UNION ALL
        SELECT pending.repository_id, pending.normalized_key,
               pending.run_id, pending.enqueued_at_ms
        FROM concurrency_group_pending_runs AS pending
        WHERE pending.run_id = candidate_run_id
    ) AS slots;

    IF concurrency_key IS NULL THEN
        exact_slot_count := 0;
    ELSE
        SELECT count(*) INTO exact_slot_count
        FROM (
            SELECT concurrency.repository_id, concurrency.normalized_key,
                   concurrency.running_run_id AS run_id,
                   concurrency.updated_at_ms AS slot_at_ms
            FROM concurrency_groups AS concurrency
            WHERE concurrency.repository_id = repository
              AND concurrency.normalized_key = concurrency_key
              AND concurrency.running_run_id = candidate_run_id
            UNION ALL
            SELECT pending.repository_id, pending.normalized_key,
                   pending.run_id, pending.enqueued_at_ms
            FROM concurrency_group_pending_runs AS pending
            WHERE pending.repository_id = repository
              AND pending.normalized_key = concurrency_key
              AND pending.run_id = candidate_run_id
        ) AS exact_slots
        WHERE exact_slots.slot_at_ms = admitted_at;
    END IF;

    IF all_slot_count <> exact_slot_count
        OR concurrency_key IS NULL AND exact_slot_count <> 0
        OR concurrency_key IS NOT NULL AND exact_slot_count <> 1
    THEN
        RAISE EXCEPTION 'workflow rerun concurrency slot is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_concurrency_slot_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_rerun_attempts_validate_concurrency_slot
AFTER INSERT ON workflow_rerun_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_rerun_concurrency_slot();

-- The source/new-job map is immutable proof that an attempt was cloned from
-- this exact terminal graph.  `selected` is the only executable closure.
CREATE TABLE workflow_rerun_attempt_jobs (
    run_id UUID NOT NULL
        REFERENCES workflow_rerun_attempts(run_id) ON DELETE RESTRICT,
    source_run_id UUID NOT NULL
        REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    logical_job_id UUID NOT NULL
        REFERENCES workflow_plan_v2_jobs(id) ON DELETE RESTRICT,
    source_logical_job_id UUID NOT NULL
        REFERENCES workflow_plan_v2_jobs(id) ON DELETE RESTRICT,
    selected BOOLEAN NOT NULL,
    PRIMARY KEY (run_id, logical_job_id),
    CONSTRAINT workflow_rerun_attempt_jobs_ids_non_nil CHECK (
        source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND source_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_rerun_attempt_jobs_source_run_fk FOREIGN KEY (
        run_id, source_run_id
    ) REFERENCES workflow_rerun_attempts(run_id, source_run_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_attempt_jobs_source_job_fk FOREIGN KEY (
        source_run_id, source_logical_job_id
    ) REFERENCES workflow_plan_v2_run_result_jobs(run_id, logical_job_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_attempt_jobs_source_unique UNIQUE (run_id, source_logical_job_id),
    CONSTRAINT workflow_rerun_attempt_jobs_exact_unique UNIQUE (
        run_id, source_run_id, logical_job_id, source_logical_job_id
    )
);

CREATE INDEX workflow_rerun_attempt_jobs_source
    ON workflow_rerun_attempt_jobs (source_run_id, source_logical_job_id);

CREATE FUNCTION automata_reject_workflow_rerun_attempt_job_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun graph evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_attempt_jobs_immutable';
END;
$automata$;

CREATE TRIGGER workflow_rerun_attempt_jobs_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_attempt_jobs
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_attempt_job_mutation();

CREATE TRIGGER workflow_rerun_attempt_jobs_no_truncate
BEFORE TRUNCATE ON workflow_rerun_attempt_jobs
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_rerun_attempt_job_mutation();

-- Unselected source terminal results are never reinterpreted as newly run
-- work.  Their original result/output/commit digests are retained as an exact
-- immutable carry-forward proof and exposed through the effective views below.
CREATE TABLE workflow_rerun_carried_job_results (
    logical_job_id UUID PRIMARY KEY
        REFERENCES workflow_plan_v2_jobs(id) ON DELETE RESTRICT,
    run_id UUID NOT NULL
        REFERENCES workflow_rerun_attempts(run_id) ON DELETE RESTRICT,
    invocation_id UUID NOT NULL,
    source_run_id UUID NOT NULL,
    source_logical_job_id UUID NOT NULL,
    result_descriptor_digest BYTEA NOT NULL,
    logical_key TEXT COLLATE "C" NOT NULL,
    source_order INTEGER NOT NULL,
    plan_digest BYTEA NOT NULL,
    plan_object_key TEXT COLLATE "C" NOT NULL,
    plan_size_bytes BIGINT NOT NULL,
    plan_media_type TEXT COLLATE "C" NOT NULL,
    plan_schema SMALLINT NOT NULL,
    activation_output_digest BYTEA NOT NULL,
    condition_matched BOOLEAN NOT NULL,
    instance_count INTEGER NOT NULL,
    instances_digest BYTEA NOT NULL,
    prerequisite_count INTEGER NOT NULL,
    prerequisites_digest BYTEA NOT NULL,
    effective_conclusion TEXT NOT NULL,
    closure_has_failure BOOLEAN NOT NULL,
    closure_has_cancelled BOOLEAN NOT NULL,
    closure_has_skipped BOOLEAN NOT NULL,
    output_count INTEGER NOT NULL,
    outputs_digest BYTEA NOT NULL,
    commit_digest BYTEA NOT NULL,
    claim_owner_id UUID NOT NULL,
    claim_generation BIGINT NOT NULL,
    claim_started_at_ms BIGINT NOT NULL,
    claim_expires_at_ms BIGINT NOT NULL,
    finalized_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_rerun_carried_job_results_target_unique
        UNIQUE (run_id, invocation_id, logical_job_id),
    CONSTRAINT workflow_rerun_carried_job_results_source_unique
        UNIQUE (run_id, source_logical_job_id),
    CONSTRAINT workflow_rerun_carried_job_results_ids_non_nil CHECK (
        invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND source_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_rerun_carried_job_results_digest_shape CHECK (
        octet_length(result_descriptor_digest) = 32
        AND octet_length(plan_digest) = 32
        AND octet_length(activation_output_digest) = 32
        AND octet_length(instances_digest) = 32
        AND octet_length(prerequisites_digest) = 32
        AND octet_length(outputs_digest) = 32
        AND octet_length(commit_digest) = 32
    ),
    CONSTRAINT workflow_rerun_carried_job_results_shape CHECK (
        source_order BETWEEN 0 AND 1023
        AND plan_size_bytes BETWEEN 1 AND 16777216
        AND plan_media_type = 'application/vnd.automata.workflow-plan+json'
        AND plan_schema = 2
        AND instance_count BETWEEN 0 AND 256
        AND prerequisite_count BETWEEN 0 AND 128
        AND output_count BETWEEN 0 AND 256
        AND effective_conclusion IN ('success', 'failure', 'cancelled', 'timed_out', 'skipped')
        AND claim_generation > 0
        AND claim_started_at_ms >= 0
        AND claim_expires_at_ms > claim_started_at_ms
        AND claim_expires_at_ms - claim_started_at_ms <= 900000
        AND finalized_at_ms >= claim_started_at_ms
        AND finalized_at_ms < claim_expires_at_ms
        AND finalized_at_ms >= 0
    ),
    CONSTRAINT workflow_rerun_carried_job_results_plan_key_shape CHECK (
        octet_length(plan_object_key) BETWEEN 1 AND 1024
        AND plan_object_key !~ '[[:cntrl:]]'
        AND left(plan_object_key, 1) <> '/'
        AND plan_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_rerun_carried_job_results_source_run_fk FOREIGN KEY (
        run_id, source_run_id
    ) REFERENCES workflow_rerun_attempts(run_id, source_run_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_carried_job_results_job_fk FOREIGN KEY (
        run_id, invocation_id, logical_job_id
    ) REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_carried_job_results_source_fk FOREIGN KEY (
        source_run_id, source_logical_job_id
    ) REFERENCES workflow_plan_v2_run_result_jobs(run_id, logical_job_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_carried_job_results_mapping_fk FOREIGN KEY (
        run_id, source_run_id, logical_job_id, source_logical_job_id
    ) REFERENCES workflow_rerun_attempt_jobs(
        run_id, source_run_id, logical_job_id, source_logical_job_id
    ) ON DELETE RESTRICT
);

CREATE TABLE workflow_rerun_carried_job_outputs (
    logical_job_id UUID NOT NULL
        REFERENCES workflow_rerun_carried_job_results(logical_job_id) ON DELETE RESTRICT,
    output_name TEXT COLLATE "C" NOT NULL,
    sensitivity TEXT NOT NULL,
    public_value TEXT,
    PRIMARY KEY (logical_job_id, output_name),
    CONSTRAINT workflow_rerun_carried_job_outputs_name_shape CHECK (
        octet_length(output_name) BETWEEN 1 AND 256
        AND btrim(output_name) = output_name
        AND output_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_rerun_carried_job_outputs_classification CHECK (
        (sensitivity = 'public' AND public_value IS NOT NULL
            AND octet_length(public_value) <= 2097152)
        OR (sensitivity = 'secret_derived' AND public_value IS NULL)
    )
);

CREATE FUNCTION automata_reject_workflow_rerun_carry_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun carry-forward evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_carry_forward_immutable';
END;
$automata$;

CREATE TRIGGER workflow_rerun_carried_job_results_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_carried_job_results
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_carry_mutation();

CREATE TRIGGER workflow_rerun_carried_job_outputs_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_carried_job_outputs
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_carry_mutation();

CREATE TRIGGER workflow_rerun_carried_job_results_no_truncate
BEFORE TRUNCATE ON workflow_rerun_carried_job_results
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_rerun_carry_mutation();

CREATE TRIGGER workflow_rerun_carried_job_outputs_no_truncate
BEFORE TRUNCATE ON workflow_rerun_carried_job_outputs
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_rerun_carry_mutation();

-- A carried result is terminal evidence, never executable pending work. Keep
-- that distinction on the logical job itself so every selector remains
-- fail-closed even if a future query forgets to join the rerun ledger.
ALTER TABLE workflow_plan_v2_jobs
    ADD COLUMN rerun_carried BOOLEAN NOT NULL DEFAULT FALSE;

CREATE OR REPLACE FUNCTION automata_require_pristine_logical_job_admission()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.rerun_carried THEN
        IF NEW.state NOT IN ('completed', 'skipped', 'cancelled', 'failed')
            OR NEW.activation_owner_id IS NOT NULL
            OR NEW.activation_claimed_at_ms IS NOT NULL
            OR NEW.activation_expires_at_ms IS NOT NULL
        THEN
            RAISE EXCEPTION 'carried logical job admission is not exact terminal evidence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_rerun_carried_job_terminal';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.state IS DISTINCT FROM 'pending'
        OR NEW.activation_fence IS DISTINCT FROM 0
        OR NEW.activation_owner_id IS NOT NULL
        OR NEW.activation_claimed_at_ms IS NOT NULL
        OR NEW.activation_expires_at_ms IS NOT NULL
        OR NEW.activation_input_digest IS NOT NULL
        OR NEW.authority_profile IS NOT NULL
        OR NEW.activation_origin_selection_id IS NOT NULL
    THEN
        RAISE EXCEPTION 'logical job admission must begin without activation authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_jobs_activation_admission_pristine';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_reject_workflow_rerun_carried_flag_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.rerun_carried IS DISTINCT FROM OLD.rerun_carried THEN
        RAISE EXCEPTION 'logical job rerun carry classification is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_jobs_rerun_carried_immutable';
    END IF;
    IF OLD.rerun_carried AND (
        NEW.state IS DISTINCT FROM OLD.state
        OR NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms
        OR NEW.activation_fence IS DISTINCT FROM OLD.activation_fence
        OR NEW.activation_owner_id IS DISTINCT FROM OLD.activation_owner_id
        OR NEW.activation_claimed_at_ms IS DISTINCT FROM OLD.activation_claimed_at_ms
        OR NEW.activation_expires_at_ms IS DISTINCT FROM OLD.activation_expires_at_ms
        OR NEW.activation_input_digest IS DISTINCT FROM OLD.activation_input_digest
        OR NEW.authority_profile IS DISTINCT FROM OLD.authority_profile
        OR NEW.activation_origin_selection_id IS DISTINCT FROM
           OLD.activation_origin_selection_id
    ) THEN
        RAISE EXCEPTION 'carried logical job execution evidence is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_rerun_carried_job_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_rerun_carried_immutable
BEFORE UPDATE OF rerun_carried, state, updated_at_ms, activation_fence,
                 activation_owner_id, activation_claimed_at_ms,
                 activation_expires_at_ms, activation_input_digest,
                 authority_profile, activation_origin_selection_id
ON workflow_plan_v2_jobs
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_carried_flag_mutation();

CREATE FUNCTION automata_validate_workflow_rerun_job_classification()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    durable_job workflow_plan_v2_jobs%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'workflow_plan_v2_jobs' THEN
        durable_job := NEW;
    ELSE
        SELECT * INTO durable_job
        FROM workflow_plan_v2_jobs
        WHERE run_id = NEW.run_id
          AND id = NEW.logical_job_id;
    END IF;

    IF durable_job.id IS NULL THEN
        RAISE EXCEPTION 'workflow rerun classification has no exact logical job'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_carried_job_exact';
    ELSIF durable_job.rerun_carried THEN
        IF EXISTS (
            SELECT 1
            FROM workflow_plan_v2_job_results AS executed
            WHERE executed.run_id = durable_job.run_id
              AND executed.logical_job_id = durable_job.id
        ) OR NOT EXISTS (
            SELECT 1
            FROM workflow_rerun_attempt_jobs AS mapping
            JOIN workflow_rerun_carried_job_results AS carried
              ON carried.run_id = mapping.run_id
             AND carried.logical_job_id = mapping.logical_job_id
             AND carried.source_run_id = mapping.source_run_id
             AND carried.source_logical_job_id = mapping.source_logical_job_id
            WHERE mapping.run_id = durable_job.run_id
              AND mapping.logical_job_id = durable_job.id
              AND NOT mapping.selected
              AND durable_job.state = CASE carried.effective_conclusion
                  WHEN 'success' THEN 'completed'
                  WHEN 'failure' THEN 'failed'
                  WHEN 'timed_out' THEN 'failed'
                  WHEN 'cancelled' THEN 'cancelled'
                  WHEN 'skipped' THEN 'skipped'
              END
        ) THEN
            RAISE EXCEPTION 'carried logical job lacks exact immutable source evidence'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'workflow_rerun_carried_job_exact';
        END IF;
    ELSIF EXISTS (
        SELECT 1
        FROM workflow_rerun_attempt_jobs AS mapping
        WHERE mapping.run_id = durable_job.run_id
          AND mapping.logical_job_id = durable_job.id
          AND NOT mapping.selected
    ) OR EXISTS (
        SELECT 1
        FROM workflow_rerun_carried_job_results AS carried
        WHERE carried.run_id = durable_job.run_id
          AND carried.logical_job_id = durable_job.id
    ) THEN
        RAISE EXCEPTION 'unselected rerun job is not classified as carried'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_carried_job_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_jobs_validate_rerun_classification
AFTER INSERT ON workflow_plan_v2_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_job_classification();

CREATE CONSTRAINT TRIGGER workflow_rerun_attempt_jobs_validate_classification
AFTER INSERT ON workflow_rerun_attempt_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_job_classification();

CREATE CONSTRAINT TRIGGER workflow_rerun_carried_results_validate_classification
AFTER INSERT ON workflow_rerun_carried_job_results
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_job_classification();

CREATE CONSTRAINT TRIGGER workflow_rerun_executed_results_validate_classification
AFTER INSERT ON workflow_plan_v2_job_results
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_job_classification();

-- Current result consumers need no mutable source lookup.  They can join this
-- view when a selected job has a carried successful prerequisite.
CREATE VIEW workflow_plan_v2_effective_job_results AS
SELECT result.logical_job_id, result.run_id, result.invocation_id,
       result.descriptor_digest, result.logical_key, result.source_order,
       result.plan_digest, result.plan_object_key, result.plan_size_bytes,
       result.plan_media_type, result.plan_schema,
       result.activation_output_digest, result.condition_matched,
       result.instance_count, result.instances_digest,
       result.prerequisite_count, result.prerequisites_digest,
       result.effective_conclusion,
       result.closure_has_failure, result.closure_has_cancelled,
       result.closure_has_skipped, result.output_count, result.outputs_digest,
       result.commit_digest, result.claim_owner_id, result.claim_generation,
       result.claim_started_at_ms, result.claim_expires_at_ms,
       result.finalized_at_ms, claim.state AS claim_state, FALSE AS carried
FROM workflow_plan_v2_job_results AS result
JOIN workflow_plan_v2_job_result_claims AS claim
  ON claim.logical_job_id = result.logical_job_id
 AND claim.state = 'finalized'
UNION ALL
SELECT carried.logical_job_id, carried.run_id, carried.invocation_id,
       carried.result_descriptor_digest AS descriptor_digest,
       carried.logical_key, carried.source_order,
       carried.plan_digest, carried.plan_object_key, carried.plan_size_bytes,
       carried.plan_media_type, carried.plan_schema,
       carried.activation_output_digest, carried.condition_matched,
       carried.instance_count, carried.instances_digest,
       carried.prerequisite_count, carried.prerequisites_digest,
       carried.effective_conclusion, carried.closure_has_failure,
       carried.closure_has_cancelled, carried.closure_has_skipped,
       carried.output_count, carried.outputs_digest, carried.commit_digest,
       carried.claim_owner_id, carried.claim_generation,
       carried.claim_started_at_ms, carried.claim_expires_at_ms,
       carried.finalized_at_ms, 'finalized'::TEXT AS claim_state, TRUE AS carried
FROM workflow_rerun_carried_job_results AS carried;

CREATE VIEW workflow_plan_v2_effective_job_result_outputs AS
SELECT output.logical_job_id, output.output_name, output.sensitivity, output.public_value
FROM workflow_plan_v2_job_result_outputs AS output
JOIN workflow_plan_v2_job_result_claims AS claim
  ON claim.logical_job_id = output.logical_job_id
 AND claim.state = 'finalized'
UNION ALL
SELECT output.logical_job_id, output.output_name, output.sensitivity, output.public_value
FROM workflow_rerun_carried_job_outputs AS output;

-- A source foreign key proves only that the source aggregate exists.  Seal
-- every carried field and classified output to that source's effective result
-- as well, including when the source is itself a partial rerun.  Deferral lets
-- the adapter insert the result before its output rows while still making a
-- forged or incomplete carry-forward impossible to commit.
CREATE FUNCTION automata_validate_workflow_rerun_carried_result_source()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    carried workflow_rerun_carried_job_results%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'workflow_rerun_carried_job_results' THEN
        carried := NEW;
    ELSE
        SELECT * INTO carried
        FROM workflow_rerun_carried_job_results
        WHERE logical_job_id = NEW.logical_job_id;
    END IF;

    IF carried.logical_job_id IS NULL OR NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_effective_job_results AS source
        WHERE source.run_id = carried.source_run_id
          AND source.logical_job_id = carried.source_logical_job_id
          AND source.claim_state = 'finalized'
          AND source.descriptor_digest = carried.result_descriptor_digest
          AND source.logical_key = carried.logical_key
          AND source.source_order = carried.source_order
          AND source.plan_digest = carried.plan_digest
          AND source.plan_object_key = carried.plan_object_key
          AND source.plan_size_bytes = carried.plan_size_bytes
          AND source.plan_media_type = carried.plan_media_type
          AND source.plan_schema = carried.plan_schema
          AND source.activation_output_digest = carried.activation_output_digest
          AND source.condition_matched = carried.condition_matched
          AND source.instance_count = carried.instance_count
          AND source.instances_digest = carried.instances_digest
          AND source.prerequisite_count = carried.prerequisite_count
          AND source.prerequisites_digest = carried.prerequisites_digest
          AND source.effective_conclusion = carried.effective_conclusion
          AND source.closure_has_failure = carried.closure_has_failure
          AND source.closure_has_cancelled = carried.closure_has_cancelled
          AND source.closure_has_skipped = carried.closure_has_skipped
          AND source.output_count = carried.output_count
          AND source.outputs_digest = carried.outputs_digest
          AND source.commit_digest = carried.commit_digest
          AND source.claim_owner_id = carried.claim_owner_id
          AND source.claim_generation = carried.claim_generation
          AND source.claim_started_at_ms = carried.claim_started_at_ms
          AND source.claim_expires_at_ms = carried.claim_expires_at_ms
          AND source.finalized_at_ms = carried.finalized_at_ms
          AND NOT EXISTS (
              (SELECT output_name, sensitivity, public_value
               FROM workflow_plan_v2_effective_job_result_outputs
               WHERE logical_job_id = carried.source_logical_job_id)
              EXCEPT
              (SELECT output_name, sensitivity, public_value
               FROM workflow_rerun_carried_job_outputs
               WHERE logical_job_id = carried.logical_job_id)
          )
          AND NOT EXISTS (
              (SELECT output_name, sensitivity, public_value
               FROM workflow_rerun_carried_job_outputs
               WHERE logical_job_id = carried.logical_job_id)
              EXCEPT
              (SELECT output_name, sensitivity, public_value
               FROM workflow_plan_v2_effective_job_result_outputs
               WHERE logical_job_id = carried.source_logical_job_id)
          )
    ) THEN
        RAISE EXCEPTION 'carried workflow result differs from its immutable source result'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_carried_job_source_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_rerun_carried_job_results_validate_source
AFTER INSERT ON workflow_rerun_carried_job_results
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_carried_result_source();

CREATE CONSTRAINT TRIGGER workflow_rerun_carried_job_outputs_validate_source
AFTER INSERT ON workflow_rerun_carried_job_outputs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_carried_result_source();

-- The immutable mapping is a total bijection, not a collection of hints.  At
-- commit every source aggregate job and every new root-invocation job must be
-- represented exactly once, the dependency graph must be an exact rename,
-- and the selected set must equal the requested downstream closure.
CREATE FUNCTION automata_validate_workflow_rerun_graph_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    candidate_run_id UUID;
    candidate_source_run_id UUID;
    exact BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'workflow_rerun_requests' THEN
        candidate_run_id := NEW.rerun_run_id;
    ELSE
        candidate_run_id := NEW.run_id;
    END IF;
    IF candidate_run_id IS NULL THEN
        RETURN NULL;
    END IF;

    SELECT source_run_id INTO candidate_source_run_id
    FROM workflow_rerun_attempts
    WHERE run_id = candidate_run_id;
    IF NOT FOUND OR candidate_source_run_id IS NULL THEN
        RETURN NULL;
    END IF;

    WITH RECURSIVE
    context AS (
        SELECT attempt.run_id, attempt.source_run_id, attempt.created_at_ms,
               target_marker.root_invocation_id AS target_invocation_id,
               source_marker.root_invocation_id AS source_invocation_id,
               request.selection_kind, request.selected_source_job_id
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.rerun_run_id = attempt.run_id
         AND request.source_run_id = attempt.source_run_id
         AND request.committed_at_ms = attempt.created_at_ms
        JOIN workflow_plan_v2_runs AS target_marker
          ON target_marker.run_id = attempt.run_id
         AND target_marker.admission_graph_sealed_at_ms IS NOT NULL
        JOIN workflow_plan_v2_runs AS source_marker
          ON source_marker.run_id = attempt.source_run_id
         AND target_marker.orchestration_schema = source_marker.orchestration_schema
         AND target_marker.runner_requirements_schema = 3
         AND source_marker.runner_requirements_schema = 3
         AND target_marker.state = 'pending'
         AND target_marker.revision = 1
         AND target_marker.admitted_at_ms = attempt.created_at_ms
         AND target_marker.updated_at_ms >= attempt.created_at_ms
         AND source_marker.base_context_digest IS NOT NULL
         AND source_marker.base_context_object_key IS NOT NULL
         AND source_marker.base_context_size_bytes IS NOT NULL
         AND source_marker.base_context_media_type =
             'application/vnd.automata.job-runtime-context.protobuf'
         AND source_marker.base_context_schema = 2
         AND target_marker.base_context_digest = source_marker.base_context_digest
         AND target_marker.base_context_object_key =
             source_marker.base_context_object_key
         AND target_marker.base_context_size_bytes =
             source_marker.base_context_size_bytes
         AND target_marker.base_context_media_type =
             source_marker.base_context_media_type
         AND target_marker.base_context_schema = source_marker.base_context_schema
        JOIN workflow_plan_v2_invocations AS target_invocation
          ON target_invocation.run_id = attempt.run_id
         AND target_invocation.id = target_marker.root_invocation_id
         AND target_invocation.invocation_kind = 'root'
         AND target_invocation.state = 'pending'
         AND target_invocation.revision = 1
         AND target_invocation.created_at_ms = attempt.created_at_ms
         AND target_invocation.updated_at_ms = attempt.created_at_ms
        JOIN human_provider_identities AS identity
          ON identity.principal_id = request.actor_principal_id
        JOIN human_sessions AS session
          ON session.tenant_id = request.tenant_id
         AND session.principal_id = request.actor_principal_id
         AND session.id = request.actor_session_id
         AND session.provider_id = identity.provider_id
         AND session.provider_subject = identity.provider_subject
        JOIN workflow_runs AS target_run
          ON target_run.id = attempt.run_id
         AND target_run.triggering_actor = identity.provider_login
         AND target_run.runner_requirements_schema = 3
         AND target_run.status = 'queued'
         AND target_run.created_at_ms = attempt.created_at_ms
         AND target_run.updated_at_ms = attempt.created_at_ms
         AND target_run.concurrency_group_key IS NULL
         AND target_run.concurrency_queue_policy IS NULL
         AND target_run.concurrency_cancel_in_progress IS NULL
        JOIN workflow_runs AS source_run
          ON source_run.id = attempt.source_run_id
         AND source_run.runner_requirements_schema = 3
         AND source_run.concurrency_group_key IS NULL
         AND source_run.concurrency_queue_policy IS NULL
         AND source_run.concurrency_cancel_in_progress IS NULL
        WHERE attempt.run_id = candidate_run_id
          AND attempt.source_run_id = candidate_source_run_id
    ),
    source_jobs AS (
        SELECT job.*
        FROM context
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = context.source_run_id
         AND job.invocation_id = context.source_invocation_id
        JOIN workflow_plan_v2_run_result_jobs AS aggregate
          ON aggregate.run_id = job.run_id
         AND aggregate.root_invocation_id = job.invocation_id
         AND aggregate.logical_job_id = job.id
    ),
    target_jobs AS (
        SELECT job.*
        FROM context
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = context.run_id
         AND job.invocation_id = context.target_invocation_id
    ),
    mapping AS (
        SELECT mapped.*
        FROM context
        JOIN workflow_rerun_attempt_jobs AS mapped
          ON mapped.run_id = context.run_id
         AND mapped.source_run_id = context.source_run_id
    ),
    expected_selected(source_logical_job_id) AS (
        SELECT source.id
        FROM context
        JOIN source_jobs AS source ON TRUE
        LEFT JOIN workflow_plan_v2_effective_job_results AS result
          ON result.run_id = context.source_run_id
         AND result.logical_job_id = source.id
         AND result.claim_state = 'finalized'
        WHERE context.selection_kind = 'entire_workflow'
           OR context.selection_kind = 'job_and_dependents'
              AND source.id = context.selected_source_job_id
           OR context.selection_kind = 'failed_jobs_and_dependents'
              AND result.effective_conclusion IN ('failure', 'timed_out')
        UNION
        SELECT dependency.logical_job_id
        FROM expected_selected AS selected
        JOIN context ON TRUE
        JOIN workflow_plan_v2_dependencies AS dependency
          ON dependency.run_id = context.source_run_id
         AND dependency.invocation_id = context.source_invocation_id
         AND dependency.prerequisite_job_id = selected.source_logical_job_id
    ),
    expected_edges AS (
        SELECT dependent.logical_job_id,
               prerequisite.logical_job_id AS prerequisite_job_id
        FROM context
        JOIN workflow_plan_v2_dependencies AS source_edge
          ON source_edge.run_id = context.source_run_id
         AND source_edge.invocation_id = context.source_invocation_id
        JOIN mapping AS dependent
          ON dependent.source_logical_job_id = source_edge.logical_job_id
        JOIN mapping AS prerequisite
          ON prerequisite.source_logical_job_id = source_edge.prerequisite_job_id
    ),
    target_edges AS (
        SELECT dependency.logical_job_id, dependency.prerequisite_job_id
        FROM context
        JOIN workflow_plan_v2_dependencies AS dependency
          ON dependency.run_id = context.run_id
         AND dependency.invocation_id = context.target_invocation_id
    )
    SELECT EXISTS (SELECT 1 FROM context)
       AND EXISTS (SELECT 1 FROM expected_selected)
       AND (SELECT count(*) FROM workflow_plan_v2_invocations AS invocation
            JOIN context ON invocation.run_id = context.source_run_id) = 1
       AND (SELECT count(*) FROM workflow_plan_v2_invocations AS invocation
            JOIN context ON invocation.run_id = context.run_id) = 1
       AND NOT EXISTS (
           SELECT 1 FROM source_jobs WHERE execution_kind <> 'steps'
       )
       AND NOT EXISTS (
           SELECT 1 FROM target_jobs WHERE execution_kind <> 'steps'
       )
       AND NOT EXISTS (
           SELECT 1
           FROM context
           JOIN workflow_plan_v2_effective_job_results AS result
             ON result.run_id = context.source_run_id
            AND result.claim_state = 'finalized'
           WHERE context.selection_kind <> 'entire_workflow'
             AND result.instance_count > 1
       )
       AND NOT EXISTS (
           (SELECT id FROM source_jobs)
           EXCEPT
           (SELECT source_logical_job_id FROM mapping)
       )
       AND NOT EXISTS (
           (SELECT source_logical_job_id FROM mapping)
           EXCEPT
           (SELECT id FROM source_jobs)
       )
       AND NOT EXISTS (
           (SELECT id FROM target_jobs)
           EXCEPT
           (SELECT logical_job_id FROM mapping)
       )
       AND NOT EXISTS (
           (SELECT logical_job_id FROM mapping)
           EXCEPT
           (SELECT id FROM target_jobs)
       )
       AND NOT EXISTS (
           (SELECT source_logical_job_id FROM mapping WHERE selected)
           EXCEPT
           (SELECT source_logical_job_id FROM expected_selected)
       )
       AND NOT EXISTS (
           (SELECT source_logical_job_id FROM expected_selected)
           EXCEPT
           (SELECT source_logical_job_id FROM mapping WHERE selected)
       )
       AND NOT EXISTS (
           SELECT 1
           FROM mapping AS mapped
           JOIN context ON TRUE
           JOIN source_jobs AS source ON source.id = mapped.source_logical_job_id
           JOIN target_jobs AS target ON target.id = mapped.logical_job_id
           WHERE target.logical_key IS DISTINCT FROM source.logical_key
              OR target.source_order IS DISTINCT FROM source.source_order
              OR target.execution_kind IS DISTINCT FROM source.execution_kind
              OR target.runtime_policy_revision IS DISTINCT FROM
                 source.runtime_policy_revision
              OR target.runtime_policy_digest IS DISTINCT FROM
                 source.runtime_policy_digest
              OR target.environment_requirement_kind IS DISTINCT FROM
                 source.environment_requirement_kind
              OR target.environment_template_digest IS DISTINCT FROM
                 source.environment_template_digest
              OR target.secret_reference_names IS DISTINCT FROM
                 source.secret_reference_names
              OR target.variable_reference_names IS DISTINCT FROM
                 source.variable_reference_names
              OR target.credential_requirements_schema IS DISTINCT FROM
                 source.credential_requirements_schema
              OR target.rerun_carried IS DISTINCT FROM NOT mapped.selected
              OR target.created_at_ms IS DISTINCT FROM context.created_at_ms
              OR target.updated_at_ms IS DISTINCT FROM context.created_at_ms
              OR mapped.selected AND (
                  target.state IS DISTINCT FROM 'pending'
                  OR target.activation_fence IS DISTINCT FROM 0
                  OR target.activation_input_digest IS NOT NULL
                  OR target.authority_profile IS NOT NULL
                  OR target.activation_origin_selection_id IS NOT NULL
              )
              OR NOT mapped.selected AND (
                  target.state IS DISTINCT FROM source.state
                  OR target.activation_fence IS DISTINCT FROM
                     source.activation_fence
                  OR target.activation_input_digest IS DISTINCT FROM
                     source.activation_input_digest
                  OR target.authority_profile IS DISTINCT FROM
                     source.authority_profile
                  OR target.activation_origin_selection_id IS DISTINCT FROM
                     source.activation_origin_selection_id
              )
       )
       AND NOT EXISTS (
           (SELECT logical_job_id, prerequisite_job_id FROM expected_edges)
           EXCEPT
           (SELECT logical_job_id, prerequisite_job_id FROM target_edges)
       )
       AND NOT EXISTS (
           (SELECT logical_job_id, prerequisite_job_id FROM target_edges)
           EXCEPT
           (SELECT logical_job_id, prerequisite_job_id FROM expected_edges)
       )
    INTO exact;

    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow rerun graph or selection closure is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_graph_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_rerun_attempts_validate_graph
AFTER INSERT ON workflow_rerun_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_graph_exact();

CREATE CONSTRAINT TRIGGER workflow_rerun_requests_validate_graph
AFTER INSERT ON workflow_rerun_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_graph_exact();

CREATE CONSTRAINT TRIGGER workflow_rerun_attempt_jobs_validate_graph
AFTER INSERT ON workflow_rerun_attempt_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_graph_exact();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_jobs_validate_rerun_graph
AFTER INSERT ON workflow_plan_v2_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_graph_exact();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_dependencies_validate_rerun_graph
AFTER INSERT ON workflow_plan_v2_dependencies
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_graph_exact();

-- Keep the signed/scheduled attempt-one origins separate, then extend the
-- stable manifest-origin view in place.  Existing trigger and authority
-- dependencies retain the view OID and therefore observe rerun attempts too.
CREATE VIEW github_workflow_run_base_manifest_origins AS
SELECT delivery_run.tenant_id,
       delivery_run.repository_id,
       delivery_run.workflow_id,
       delivery_run.snapshot_id,
       delivery_run.run_id,
       delivery_run.root_invocation_id,
       'provider_delivery'::TEXT AS origin_kind,
       delivery_run.provider_delivery_id AS origin_id,
       'provider_delivery'::TEXT AS admission_idempotency_kind,
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
       delivery.private_source_authority_id,
       delivery.private_source_authority_identity_digest,
       delivery.private_source_authority_app_configuration_revision,
       delivery.private_source_authority_policy_revision
FROM github_workflow_run_subject_evidence AS delivery_run
JOIN github_provider_delivery_evidence AS delivery
  ON delivery.tenant_id = delivery_run.tenant_id
 AND delivery.repository_id = delivery_run.repository_id
 AND delivery.provider_delivery_id = delivery_run.provider_delivery_id
UNION ALL
SELECT schedule_run.tenant_id,
       schedule_run.repository_id,
       schedule_run.workflow_id,
       schedule_run.snapshot_id,
       schedule_run.run_id,
       schedule_run.root_invocation_id,
       'scheduled_fire'::TEXT AS origin_kind,
       schedule_run.schedule_fire_id AS origin_id,
       'operation'::TEXT AS admission_idempotency_kind,
       schedule_run.schedule_fire_id::TEXT AS admission_idempotency_key,
       schedule_run.github_check_subject_id,
       schedule_run.github_check_head_sha,
       schedule_run.workflow_path,
       schedule_run.source_digest,
       schedule_run.event_name,
       schedule_run.event_digest,
       schedule_run.git_ref,
       schedule_run.workflow_plan_schema,
       schedule_run.plan_digest,
       schedule_run.logical_admission_digest,
       schedule_run.admitted_at_ms,
       schedule_run.subject_evidence_sha256,
       schedule_check.provider_connection_id,
       manifest.provider_installation_id,
       manifest.github_repository_id,
       schedule_run.github_repository_owner_id,
       manifest.github_repository_name,
       manifest.repository_visibility,
       schedule_check.provider_manifest_revision,
       schedule_check.provider_manifest_digest,
       manifest.webhook_verifier_fingerprint_sha256,
       manifest.webhook_verifier_revision,
       schedule_check.checks_authority_id,
       schedule_check.checks_authority_identity_digest,
       schedule_check.checks_authority_app_configuration_revision,
       schedule_check.checks_authority_policy_revision,
       registry.private_source_authority_id,
       registry.private_source_authority_identity_digest,
       registry.private_source_authority_app_configuration_revision,
       registry.private_source_authority_policy_revision
FROM github_schedule_workflow_run_subject_evidence AS schedule_run
JOIN github_schedule_check_evidence AS schedule_check
  ON schedule_check.schedule_fire_id = schedule_run.schedule_fire_id
 AND schedule_check.tenant_id = schedule_run.tenant_id
 AND schedule_check.repository_id = schedule_run.repository_id
 AND schedule_check.github_check_subject_id = schedule_run.github_check_subject_id
JOIN github_schedule_registry_revisions AS registry
  ON registry.tenant_id = schedule_check.tenant_id
 AND registry.repository_id = schedule_check.repository_id
 AND registry.provider_connection_id = schedule_check.provider_connection_id
 AND registry.registry_id = schedule_check.registry_id
 AND registry.manifest_revision = schedule_check.provider_manifest_revision
 AND registry.manifest_digest = schedule_check.provider_manifest_digest
 AND registry.default_branch_ref = schedule_check.default_branch_ref
 AND registry.source_revision = schedule_check.source_revision
JOIN github_provider_manifest_revisions AS manifest
  ON manifest.tenant_id = schedule_check.tenant_id
 AND manifest.repository_id = schedule_check.repository_id
 AND manifest.provider_connection_id = schedule_check.provider_connection_id
 AND manifest.manifest_revision = schedule_check.provider_manifest_revision
 AND manifest.manifest_digest = schedule_check.provider_manifest_digest;

-- Every physical rerun owns a fresh provider Check subject.  It is neither a
-- second signed delivery subject nor a synthetic scheduled fire: its closed
-- origin is the immutable rerun attempt. Its immutable source manifest is
-- retained while a live matching checks-write authority is selected anew.
ALTER TABLE github_check_subjects
    DROP CONSTRAINT github_check_subjects_origin_exact,
    ADD COLUMN workflow_rerun_run_id UUID,
    ADD CONSTRAINT github_check_subjects_workflow_rerun_run
        FOREIGN KEY (tenant_id, workflow_rerun_run_id)
        REFERENCES workflow_rerun_requests(tenant_id, rerun_run_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT github_check_subjects_workflow_rerun_unique
        UNIQUE (workflow_rerun_run_id),
    ADD CONSTRAINT github_check_subjects_workflow_rerun_identity_unique
        UNIQUE (
            tenant_id, repository_id, provider_connection_id,
            workflow_rerun_run_id, id
        ),
    ADD CONSTRAINT github_check_subjects_workflow_rerun_non_nil CHECK (
        workflow_rerun_run_id IS NULL
        OR workflow_rerun_run_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
    ),
    ADD CONSTRAINT github_check_subjects_origin_exact CHECK (
        num_nonnulls(
            provider_delivery_id, schedule_fire_id, workflow_rerun_run_id
        ) = 1
        AND (
            origin_kind = 'provider_delivery'
            AND provider_delivery_id IS NOT NULL
            AND schedule_fire_id IS NULL
            AND workflow_rerun_run_id IS NULL
            OR origin_kind = 'scheduled_fire'
            AND provider_delivery_id IS NULL
            AND schedule_fire_id IS NOT NULL
            AND workflow_rerun_run_id IS NULL
            OR origin_kind = 'workflow_rerun'
            AND provider_delivery_id IS NULL
            AND schedule_fire_id IS NULL
            AND workflow_rerun_run_id IS NOT NULL
        )
    );

CREATE TABLE workflow_rerun_check_evidence (
    run_id UUID PRIMARY KEY,
    source_run_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    provider_manifest_revision BIGINT NOT NULL,
    provider_manifest_digest BYTEA NOT NULL,
    source_github_check_subject_id UUID NOT NULL,
    github_check_subject_id UUID NOT NULL UNIQUE,
    github_check_head_sha BYTEA NOT NULL,
    checks_authority_id UUID NOT NULL,
    checks_authority_identity_digest BYTEA NOT NULL,
    checks_authority_app_configuration_revision BIGINT NOT NULL,
    checks_authority_policy_revision BIGINT NOT NULL,
    private_source_authority_id UUID,
    private_source_authority_identity_digest BYTEA,
    private_source_authority_app_configuration_revision BIGINT,
    private_source_authority_policy_revision BIGINT,
    recorded_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_rerun_check_evidence_attempt_source FOREIGN KEY (
        run_id, source_run_id
    ) REFERENCES workflow_rerun_attempts(run_id, source_run_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_check_evidence_request FOREIGN KEY (
        tenant_id, operation_id, run_id
    ) REFERENCES workflow_rerun_requests(
        tenant_id, operation_id, rerun_run_id
    ) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_check_evidence_tenant_repository FOREIGN KEY (
        tenant_id, repository_id
    ) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_check_evidence_manifest FOREIGN KEY (
        tenant_id, repository_id, provider_connection_id,
        provider_manifest_revision, provider_manifest_digest
    ) REFERENCES github_provider_manifest_revisions(
        tenant_id, repository_id, provider_connection_id,
        manifest_revision, manifest_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_check_evidence_source_subject FOREIGN KEY (
        tenant_id, source_github_check_subject_id
    ) REFERENCES github_check_subjects(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_check_evidence_subject FOREIGN KEY (
        tenant_id, repository_id, provider_connection_id,
        run_id, github_check_subject_id
    ) REFERENCES github_check_subjects(
        tenant_id, repository_id, provider_connection_id,
        workflow_rerun_run_id, id
    ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT workflow_rerun_check_evidence_authority FOREIGN KEY (
        tenant_id, checks_authority_id
    ) REFERENCES github_server_service_authorities(tenant_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_check_evidence_private_authority FOREIGN KEY (
        tenant_id, private_source_authority_id
    ) REFERENCES github_server_service_authorities(tenant_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_check_evidence_ids_non_nil CHECK (
        run_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND source_run_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND operation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND provider_connection_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND source_github_check_subject_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND github_check_subject_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND checks_authority_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND (
            private_source_authority_id IS NULL
            OR private_source_authority_id <>
                '00000000-0000-0000-0000-000000000000'::UUID
        )
    ),
    CONSTRAINT workflow_rerun_check_evidence_shape CHECK (
        provider_manifest_revision > 0
        AND octet_length(provider_manifest_digest) = 32
        AND octet_length(github_check_head_sha) = 20
        AND github_check_head_sha <>
            pg_catalog.decode(repeat('00', 20), 'hex')
        AND octet_length(checks_authority_identity_digest) = 32
        AND checks_authority_app_configuration_revision > 0
        AND checks_authority_policy_revision > 0
        AND num_nonnulls(
            private_source_authority_id,
            private_source_authority_identity_digest,
            private_source_authority_app_configuration_revision,
            private_source_authority_policy_revision
        ) IN (0, 4)
        AND (
            private_source_authority_identity_digest IS NULL
            OR octet_length(private_source_authority_identity_digest) = 32
            AND private_source_authority_app_configuration_revision > 0
            AND private_source_authority_policy_revision > 0
        )
        AND recorded_at_ms >= 0
    ),
    CONSTRAINT workflow_rerun_check_evidence_exact_subject_unique UNIQUE (
        tenant_id, run_id, github_check_subject_id
    )
);

CREATE FUNCTION automata_reject_workflow_rerun_check_evidence_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun Check evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workflow_rerun_check_evidence_immutable';
END;
$automata$;

CREATE TRIGGER workflow_rerun_check_evidence_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_check_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_rerun_check_evidence_mutation();

CREATE TRIGGER workflow_rerun_check_evidence_no_truncate
BEFORE TRUNCATE ON workflow_rerun_check_evidence
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_rerun_check_evidence_mutation();

CREATE FUNCTION automata_github_workflow_rerun_subject_evidence_digest(
    operation_id UUID,
    tenant_id TEXT,
    repository_id UUID,
    workflow_id UUID,
    snapshot_id UUID,
    run_id UUID,
    source_run_id UUID,
    root_invocation_id UUID,
    github_repository_owner_id BIGINT,
    github_check_subject_id UUID,
    github_check_head_sha BYTEA,
    workflow_path TEXT,
    source_digest BYTEA,
    event_name TEXT,
    event_digest BYTEA,
    git_ref TEXT,
    workflow_plan_schema SMALLINT,
    plan_digest BYTEA,
    logical_admission_digest BYTEA,
    admitted_at_ms BIGINT
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.github-workflow-rerun-subject-evidence.v1', 'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(operation_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(tenant_id, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(repository_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(workflow_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(snapshot_id)
    )
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(run_id))
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(source_run_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(root_invocation_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(github_repository_owner_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(github_check_subject_id)
    )
    || automata_github_provider_manifest_digest_part(github_check_head_sha)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(workflow_path, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(source_digest)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(event_name, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(event_digest)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(git_ref, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(workflow_plan_schema::BIGINT)
    )
    || automata_github_provider_manifest_digest_part(plan_digest)
    || automata_github_provider_manifest_digest_part(logical_admission_digest)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(admitted_at_ms)
    )
)
$automata$;

CREATE TABLE github_workflow_rerun_subject_evidence (
    operation_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    workflow_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,
    run_id UUID NOT NULL,
    source_run_id UUID NOT NULL,
    root_invocation_id UUID NOT NULL,
    github_repository_owner_id BIGINT NOT NULL,
    github_check_subject_id UUID NOT NULL,
    github_check_head_sha BYTEA NOT NULL,
    workflow_path TEXT COLLATE "C" NOT NULL,
    source_digest BYTEA NOT NULL,
    event_name TEXT COLLATE "C" NOT NULL,
    event_digest BYTEA NOT NULL,
    git_ref TEXT COLLATE "C" NOT NULL,
    workflow_plan_schema SMALLINT NOT NULL,
    plan_digest BYTEA NOT NULL,
    logical_admission_digest BYTEA NOT NULL,
    admitted_at_ms BIGINT NOT NULL,
    subject_evidence_sha256 BYTEA GENERATED ALWAYS AS (
        automata_github_workflow_rerun_subject_evidence_digest(
            operation_id, tenant_id, repository_id, workflow_id,
            snapshot_id, run_id, source_run_id, root_invocation_id,
            github_repository_owner_id, github_check_subject_id,
            github_check_head_sha, workflow_path, source_digest,
            event_name, event_digest, git_ref, workflow_plan_schema,
            plan_digest, logical_admission_digest, admitted_at_ms
        )
    ) STORED,
    CONSTRAINT github_workflow_rerun_subject_evidence_primary_key
        PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT github_workflow_rerun_subject_evidence_run_unique
        UNIQUE (repository_id, run_id),
    CONSTRAINT github_workflow_rerun_subject_evidence_subject_unique
        UNIQUE (github_check_subject_id),
    CONSTRAINT github_workflow_rerun_subject_evidence_request FOREIGN KEY (
        tenant_id, operation_id, run_id
    ) REFERENCES workflow_rerun_requests(
        tenant_id, operation_id, rerun_run_id
    ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_rerun_subject_evidence_attempt FOREIGN KEY (
        run_id, source_run_id
    ) REFERENCES workflow_rerun_attempts(run_id, source_run_id)
        ON DELETE RESTRICT,
    CONSTRAINT github_workflow_rerun_subject_evidence_repository FOREIGN KEY (
        tenant_id, repository_id
    ) REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_rerun_subject_evidence_run FOREIGN KEY (
        repository_id, run_id
    ) REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_rerun_subject_evidence_workflow FOREIGN KEY (
        repository_id, workflow_id
    ) REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_rerun_subject_evidence_snapshot FOREIGN KEY (
        snapshot_id, workflow_id
    ) REFERENCES workflow_snapshots(id, workflow_id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_rerun_subject_evidence_check FOREIGN KEY (
        tenant_id, run_id, github_check_subject_id
    ) REFERENCES workflow_rerun_check_evidence(
        tenant_id, run_id, github_check_subject_id
    ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_rerun_subject_evidence_non_nil CHECK (
        operation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND workflow_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND snapshot_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND run_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND source_run_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND root_invocation_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND github_check_subject_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT github_workflow_rerun_subject_evidence_shape CHECK (
        github_repository_owner_id > 0
        AND octet_length(github_check_head_sha) = 20
        AND github_check_head_sha <>
            pg_catalog.decode(repeat('00', 20), 'hex')
        AND octet_length(source_digest) = 32
        AND octet_length(event_name) BETWEEN 1 AND 1024
        AND event_name !~ '[[:cntrl:]]'
        AND octet_length(event_digest) = 32
        AND automata_github_provider_git_ref_canonical(git_ref)
        AND workflow_plan_schema = 2
        AND octet_length(plan_digest) = 32
        AND octet_length(logical_admission_digest) = 32
        AND admitted_at_ms >= 0
        AND octet_length(subject_evidence_sha256) = 32
        AND workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'
        AND workflow_path !~ '[[:cntrl:]\\]'
    )
);

CREATE FUNCTION automata_reject_workflow_rerun_subject_evidence_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun run-subject evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_workflow_rerun_subject_evidence_immutable';
END;
$automata$;

CREATE TRIGGER github_workflow_rerun_subject_evidence_no_update_delete
BEFORE UPDATE OR DELETE ON github_workflow_rerun_subject_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_rerun_subject_evidence_mutation();

CREATE TRIGGER github_workflow_rerun_subject_evidence_no_truncate
BEFORE TRUNCATE ON github_workflow_rerun_subject_evidence
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_rerun_subject_evidence_mutation();

CREATE OR REPLACE FUNCTION automata_github_check_subject_origin_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.origin_kind IS DISTINCT FROM OLD.origin_kind
        OR NEW.provider_delivery_id IS DISTINCT FROM OLD.provider_delivery_id
        OR NEW.schedule_fire_id IS DISTINCT FROM OLD.schedule_fire_id
        OR NEW.workflow_rerun_run_id IS DISTINCT FROM OLD.workflow_rerun_run_id
    THEN
        RAISE EXCEPTION 'GitHub Check subject origin is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_github_check_subject_canonical_name()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    canonical_name TEXT;
BEGIN
    SELECT * INTO repository
    FROM repositories
    WHERE id = NEW.repository_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;

    IF NEW.origin_kind = 'provider_delivery' THEN
        SELECT * INTO delivery
        FROM provider_delivery_inbox
        WHERE id = NEW.provider_delivery_id
          AND tenant_id = NEW.tenant_id
        FOR SHARE;
        IF delivery.id IS NULL
            OR repository.id IS NULL
            OR delivery.provider <> 'github'
            OR delivery.provider_repository_id <> NEW.github_repository_id
            OR delivery.repository_identity <>
                repository.owner || '/' || repository.name
        THEN
            RAISE EXCEPTION 'GitHub Check canonical repository identity is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_canonical_name_exact';
        END IF;
        NEW.github_repository_name := delivery.repository_identity;
    ELSIF NEW.origin_kind = 'scheduled_fire' THEN
        SELECT manifest.github_repository_name INTO canonical_name
        FROM github_schedule_fires AS fire
        JOIN github_schedule_registry_revisions AS registry
          ON registry.tenant_id = fire.tenant_id
         AND registry.repository_id = fire.repository_id
         AND registry.provider_connection_id = fire.provider_connection_id
         AND registry.registry_id = fire.registry_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = registry.tenant_id
         AND manifest.repository_id = registry.repository_id
         AND manifest.provider_connection_id = registry.provider_connection_id
         AND manifest.manifest_revision = registry.manifest_revision
         AND manifest.manifest_digest = registry.manifest_digest
        JOIN github_provider_manifest_current AS manifest_current
          ON manifest_current.tenant_id = manifest.tenant_id
         AND manifest_current.repository_id = manifest.repository_id
         AND manifest_current.provider_connection_id = manifest.provider_connection_id
         AND manifest_current.manifest_revision = manifest.manifest_revision
         AND manifest_current.manifest_digest = manifest.manifest_digest
        WHERE fire.fire_id = NEW.schedule_fire_id
          AND fire.tenant_id = NEW.tenant_id
          AND fire.repository_id = NEW.repository_id
          AND fire.provider_connection_id = NEW.provider_connection_id
        FOR SHARE OF fire, registry, manifest, manifest_current;
        IF canonical_name IS NULL
            OR repository.id IS NULL
            OR repository.scm_provider <> 'github'
            OR repository.provider_repository_id <>
                NEW.github_repository_id::TEXT
            OR canonical_name <> repository.owner || '/' || repository.name
        THEN
            RAISE EXCEPTION 'GitHub Check canonical repository identity is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_canonical_name_exact';
        END IF;
        NEW.github_repository_name := canonical_name;
    ELSIF NEW.origin_kind = 'workflow_rerun' THEN
        SELECT source.github_repository_name INTO canonical_name
        FROM workflow_rerun_attempts AS attempt
        JOIN github_check_subjects AS source
          ON source.workflow_run_id = attempt.source_run_id
        WHERE attempt.run_id = NEW.workflow_rerun_run_id
          AND attempt.source_run_id IS NOT NULL
          AND source.desired_state = 'completed'
          AND source.desired_revision = 3
          AND 1 = (
              SELECT count(*)
              FROM github_check_subjects AS exact_source
              WHERE exact_source.workflow_run_id = attempt.source_run_id
          )
        FOR SHARE OF attempt, source;
        IF canonical_name IS NULL
            OR repository.id IS NULL
            OR repository.scm_provider <> 'github'
            OR repository.provider_repository_id <>
                NEW.github_repository_id::TEXT
            OR canonical_name <> repository.owner || '/' || repository.name
        THEN
            RAISE EXCEPTION 'GitHub rerun Check canonical identity is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_canonical_name_exact';
        END IF;
        NEW.github_repository_name := canonical_name;
    ELSE
        RAISE EXCEPTION 'GitHub Check subject origin is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Manual workflow dispatches are authenticated control-plane admissions, not
-- provider deliveries. Preserve the existing manifest-origin provenance for
-- webhook and scheduled runs while admitting a dispatch pin only when its
-- append-only human audit and exact current sealed manifest policy agree.
CREATE OR REPLACE FUNCTION automata_require_workflow_runtime_policy_pin_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM github_workflow_run_manifest_origins AS origin
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = origin.tenant_id
     AND manifest.repository_id = origin.repository_id
     AND manifest.provider_connection_id = origin.provider_connection_id
     AND manifest.manifest_revision = origin.provider_manifest_revision
     AND manifest.manifest_digest = origin.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = manifest.tenant_id
     AND policy.repository_id = manifest.repository_id
     AND policy.policy_revision = manifest.runtime_policy_revision
     AND policy.policy_digest = manifest.runtime_policy_digest
     AND policy.state = 'sealed'
    JOIN workflow_runs AS run
      ON run.id = origin.run_id
     AND run.repository_id = origin.repository_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = origin.run_id
    WHERE origin.run_id = NEW.run_id
      AND origin.tenant_id = NEW.tenant_id
      AND origin.repository_id = NEW.repository_id
      AND origin.admitted_at_ms = NEW.pinned_at_ms
      AND manifest.runtime_policy_revision = NEW.policy_revision
      AND manifest.runtime_policy_digest = NEW.policy_digest
    FOR SHARE OF manifest, policy, run, marker;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_runs AS run
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
    JOIN security_audit_events AS audit
      ON audit.tenant_id = NEW.tenant_id
     AND audit.action = 'workflow.dispatch'
     AND audit.outcome = 'succeeded'
     AND audit.resource_kind = 'workflow_run'
     AND audit.resource_id = NEW.run_id::TEXT
     AND audit.occurred_at_ms = NEW.pinned_at_ms
     AND audit.actor_kind = 'human'
     AND audit.actor_principal_id IS NOT NULL
     AND audit.actor_session_id IS NOT NULL
     AND audit.authorization_revision IS NOT NULL
    JOIN github_provider_manifest_current AS current_manifest
      ON current_manifest.tenant_id = NEW.tenant_id
     AND current_manifest.repository_id = NEW.repository_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = current_manifest.tenant_id
     AND manifest.repository_id = current_manifest.repository_id
     AND manifest.provider_connection_id = current_manifest.provider_connection_id
     AND manifest.manifest_revision = current_manifest.manifest_revision
     AND manifest.manifest_digest = current_manifest.manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = manifest.tenant_id
     AND policy.repository_id = manifest.repository_id
     AND policy.policy_revision = manifest.runtime_policy_revision
     AND policy.policy_digest = manifest.runtime_policy_digest
     AND policy.state = 'sealed'
    WHERE run.id = NEW.run_id
      AND run.repository_id = NEW.repository_id
      AND manifest.runtime_policy_revision = NEW.policy_revision
      AND manifest.runtime_policy_digest = NEW.policy_digest
    FOR SHARE OF run, marker, audit, current_manifest, manifest, policy;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow runtime policy pin lacks authenticated manifest provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_runtime_policy_pin_provenance';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_github_check_subject_delivery_evidence_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    authority RECORD;
    workflow_authorized BOOLEAN := FALSE;
BEGIN
    IF NEW.origin_kind IN ('scheduled_fire', 'workflow_rerun') THEN
        RETURN NEW;
    END IF;
    SELECT evidence_source.repository_id,
           evidence_source.provider_connection_id,
           evidence_source.provider_installation_id,
           evidence_source.github_repository_id,
           evidence_source.github_repository_name,
           evidence_source.github_check_subject_id,
           evidence_source.github_check_head_sha,
           inbox_source.accepted_at_ms,
           inbox_source.state AS inbox_state,
           manifest_source.workflow_selection_kind,
           manifest_source.check_subject_key,
           manifest_source.github_app_id,
           manifest_source.check_name,
           manifest_source.manifest_digest
      INTO authority
    FROM github_provider_delivery_evidence AS evidence_source
    JOIN provider_delivery_inbox AS inbox_source
      ON inbox_source.id = evidence_source.provider_delivery_id
     AND inbox_source.tenant_id = evidence_source.tenant_id
    JOIN github_provider_manifest_revisions AS manifest_source
      ON manifest_source.tenant_id = evidence_source.tenant_id
     AND manifest_source.repository_id = evidence_source.repository_id
     AND manifest_source.provider_connection_id =
         evidence_source.provider_connection_id
     AND manifest_source.manifest_revision =
         evidence_source.provider_manifest_revision
     AND manifest_source.manifest_digest =
         evidence_source.provider_manifest_digest
    WHERE evidence_source.provider_delivery_id = NEW.provider_delivery_id
      AND evidence_source.tenant_id = NEW.tenant_id
    FOR SHARE OF evidence_source, inbox_source, manifest_source;

    IF FOUND
       AND authority.workflow_selection_kind = 'all_direct'
       AND NEW.id <> authority.github_check_subject_id
    THEN
        SELECT TRUE INTO workflow_authorized
        FROM provider_delivery_workflow_inventories AS inventory
        JOIN provider_delivery_workflow_inventory_entries AS entry
          ON entry.inbox_id = inventory.inbox_id
         AND entry.tenant_id = inventory.tenant_id
        WHERE inventory.inbox_id = NEW.provider_delivery_id
          AND inventory.tenant_id = NEW.tenant_id
          AND inventory.manifest_digest = authority.manifest_digest
          AND entry.workflow_path = NEW.subject_key
          AND (
              entry.source_state = 'ready'
              OR EXISTS (
                  SELECT 1
                  FROM provider_delivery_workflow_progress AS progress
                  WHERE progress.inbox_id = inventory.inbox_id
                    AND progress.tenant_id = inventory.tenant_id
                    AND progress.inventory_digest = inventory.inventory_digest
                    AND progress.workflow_path = entry.workflow_path
                    AND progress.outcome_kind = 'failed'
              )
          )
        FOR SHARE OF inventory, entry;
    END IF;

    IF authority.repository_id IS NULL
        OR NEW.origin_kind <> 'provider_delivery'
        OR NEW.repository_id <> authority.repository_id
        OR NEW.provider_connection_id <> authority.provider_connection_id
        OR NEW.provider_installation_id <> authority.provider_installation_id
        OR NEW.github_repository_id <> authority.github_repository_id
        OR NEW.github_repository_name <> authority.github_repository_name
        OR NEW.github_app_id <> authority.github_app_id
        OR NEW.head_sha <> authority.github_check_head_sha
        OR NEW.check_name <> authority.check_name
        OR NEW.created_at_ms <> authority.accepted_at_ms
        OR NOT (
            NEW.id = authority.github_check_subject_id
            AND NEW.subject_key = authority.check_subject_key
            OR authority.workflow_selection_kind = 'all_direct'
            AND authority.inbox_state = 'claimed'
            AND NEW.id <> authority.github_check_subject_id
            AND workflow_authorized
        )
    THEN
        RAISE EXCEPTION 'GitHub Check subject does not match its signed delivery evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_delivery_evidence_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_github_check_subject_insert_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    schedule RECORD;
    rerun RECORD;
    now_ms BIGINT;
BEGIN
    IF NEW.desired_state <> 'queued'
        OR NEW.desired_revision <> 1
        OR NEW.desired_updated_at_ms <> NEW.created_at_ms
        OR NEW.workflow_run_id IS NOT NULL
        OR NEW.linked_at_ms IS NOT NULL
    THEN
        RAISE EXCEPTION 'GitHub Check subjects must begin queued and unlinked'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_initial_state';
    END IF;

    SELECT * INTO repository
    FROM repositories
    WHERE id = NEW.repository_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    IF repository.id IS NULL
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner || '/' || repository.name <>
            NEW.github_repository_name
    THEN
        RAISE EXCEPTION 'GitHub Check subject repository is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_authority_exact';
    END IF;

    IF NEW.origin_kind = 'provider_delivery' THEN
        SELECT * INTO delivery
        FROM provider_delivery_inbox
        WHERE id = NEW.provider_delivery_id
          AND tenant_id = NEW.tenant_id
        FOR SHARE;
        IF delivery.id IS NULL
            OR delivery.provider <> 'github'
            OR delivery.connection_id <> NEW.provider_connection_id
            OR delivery.installation_id <> NEW.provider_installation_id
            OR delivery.provider_repository_id <> NEW.github_repository_id
        THEN
            RAISE EXCEPTION 'GitHub Check delivery authority is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_authority_exact';
        END IF;
    ELSIF NEW.origin_kind = 'scheduled_fire' THEN
        now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
        SELECT fire.fire_id,
               fire.state AS fire_state,
               fire.claimed_at_ms,
               fire.claim_expires_at_ms,
               registry.source_revision,
               registry.default_branch_ref,
               entry.workflow_path,
               seal.registry_id AS sealed_registry_id,
               current.registry_id AS current_registry_id,
               manifest.provider_installation_id,
               manifest.github_repository_id,
               manifest.github_repository_name,
               manifest.github_app_id,
               manifest.check_name,
               manifest.git_ref
          INTO schedule
        FROM github_schedule_fires AS fire
        JOIN github_schedule_registry_revisions AS registry
          ON registry.tenant_id = fire.tenant_id
         AND registry.repository_id = fire.repository_id
         AND registry.provider_connection_id = fire.provider_connection_id
         AND registry.registry_id = fire.registry_id
        JOIN github_schedule_registry_entries AS entry
          ON entry.registry_id = fire.registry_id
         AND entry.ordinal = fire.entry_ordinal
        JOIN github_schedule_registry_seals AS seal
          ON seal.registry_id = registry.registry_id
         AND seal.inventory_digest = registry.inventory_digest
         AND seal.schedule_count = registry.schedule_count
        JOIN github_schedule_registry_current AS current
          ON current.tenant_id = registry.tenant_id
         AND current.repository_id = registry.repository_id
         AND current.provider_connection_id = registry.provider_connection_id
         AND current.registry_id = registry.registry_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = registry.tenant_id
         AND manifest.repository_id = registry.repository_id
         AND manifest.provider_connection_id = registry.provider_connection_id
         AND manifest.manifest_revision = registry.manifest_revision
         AND manifest.manifest_digest = registry.manifest_digest
        JOIN github_provider_manifest_current AS manifest_current
          ON manifest_current.tenant_id = manifest.tenant_id
         AND manifest_current.repository_id = manifest.repository_id
         AND manifest_current.provider_connection_id = manifest.provider_connection_id
         AND manifest_current.manifest_revision = manifest.manifest_revision
         AND manifest_current.manifest_digest = manifest.manifest_digest
        WHERE fire.fire_id = NEW.schedule_fire_id
          AND fire.tenant_id = NEW.tenant_id
          AND fire.repository_id = NEW.repository_id
          AND fire.provider_connection_id = NEW.provider_connection_id
        FOR SHARE OF fire, registry, entry, seal, current, manifest,
                     manifest_current;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'GitHub scheduled Check has no exact sealed fire'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_schedule_authority_exact';
        END IF;
        IF schedule.fire_state <> 'claimed'
            OR schedule.claimed_at_ms > now_ms
            OR schedule.claim_expires_at_ms <= now_ms
            OR NEW.created_at_ms < schedule.claimed_at_ms
            OR NEW.created_at_ms >= schedule.claim_expires_at_ms
            OR schedule.default_branch_ref <> schedule.git_ref
            OR NEW.subject_key <> schedule.workflow_path
            OR NEW.provider_installation_id <>
                schedule.provider_installation_id
            OR NEW.github_repository_id <> schedule.github_repository_id
            OR NEW.github_repository_name <> schedule.github_repository_name
            OR NEW.github_app_id <> schedule.github_app_id
            OR NEW.head_sha <> decode(schedule.source_revision, 'hex')
            OR NEW.check_name <> schedule.check_name
        THEN
            RAISE EXCEPTION 'GitHub scheduled Check authority is not exact and live'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_schedule_authority_exact';
        END IF;
    ELSIF NEW.origin_kind = 'workflow_rerun' THEN
        SELECT attempt.run_id,
               attempt.source_run_id,
               attempt.created_at_ms,
               request.tenant_id,
               request.repository_id,
               request.committed_at_ms,
               run.head_sha AS run_head_sha,
               run.status AS run_status,
               source.id AS source_subject_id,
               source.tenant_id AS source_tenant_id,
               source.repository_id AS source_repository_id,
               source.subject_key AS source_subject_key,
               source.provider_connection_id AS source_connection_id,
               source.provider_installation_id AS source_installation_id,
               source.github_repository_id AS source_repository_provider_id,
               source.github_repository_name AS source_repository_name,
               source.github_app_id AS source_app_id,
               source.head_sha AS source_head_sha,
               source.check_name AS source_check_name,
               source.desired_state AS source_desired_state,
               source.desired_revision AS source_desired_revision
          INTO rerun
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.rerun_run_id = attempt.run_id
         AND request.source_run_id = attempt.source_run_id
        JOIN workflow_runs AS run ON run.id = attempt.run_id
        JOIN github_check_subjects AS source
          ON source.workflow_run_id = attempt.source_run_id
        WHERE attempt.run_id = NEW.workflow_rerun_run_id
          AND attempt.source_run_id IS NOT NULL
          AND 1 = (
              SELECT count(*)
              FROM github_check_subjects AS exact_source
              WHERE exact_source.workflow_run_id = attempt.source_run_id
          )
        FOR SHARE OF attempt, request, run, source;
        IF NOT FOUND
            OR rerun.tenant_id <> NEW.tenant_id
            OR rerun.repository_id <> NEW.repository_id
            OR rerun.committed_at_ms <> rerun.created_at_ms
            OR rerun.run_status <> 'queued'
            OR rerun.run_head_sha <> NEW.head_sha
            OR rerun.source_tenant_id <> NEW.tenant_id
            OR rerun.source_repository_id <> NEW.repository_id
            OR rerun.source_desired_state <> 'completed'
            OR rerun.source_desired_revision <> 3
            OR NEW.created_at_ms <> rerun.created_at_ms
            OR NEW.subject_key <> rerun.source_subject_key
            OR NEW.provider_connection_id <> rerun.source_connection_id
            OR NEW.provider_installation_id <> rerun.source_installation_id
            OR NEW.github_repository_id <>
                rerun.source_repository_provider_id
            OR NEW.github_repository_name <> rerun.source_repository_name
            OR NEW.github_app_id <> rerun.source_app_id
            OR NEW.head_sha <> rerun.source_head_sha
            OR NEW.check_name <> rerun.source_check_name
        THEN
            RAISE EXCEPTION 'GitHub rerun Check authority is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_rerun_authority_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub Check subject origin is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_validate_workflow_rerun_check_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    exact BOOLEAN;
    private_exact BOOLEAN := TRUE;
BEGIN
    SELECT TRUE INTO exact
    FROM workflow_rerun_attempts AS attempt
    JOIN workflow_rerun_requests AS request
      ON request.tenant_id = NEW.tenant_id
     AND request.operation_id = NEW.operation_id
     AND request.rerun_run_id = attempt.run_id
     AND request.source_run_id = attempt.source_run_id
    JOIN workflow_admission_receipts AS receipt
      ON receipt.tenant_id = request.tenant_id
     AND receipt.idempotency_kind = 'operation'
     AND receipt.idempotency_key =
         'workflow-rerun:' || request.operation_id::TEXT
     AND receipt.request_digest = request.request_digest
     AND receipt.repository_id = request.repository_id
     AND receipt.run_id = attempt.run_id
     AND receipt.committed_at_ms = attempt.created_at_ms
     AND receipt.github_subject_evidence_required
    JOIN workflow_runs AS run ON run.id = attempt.run_id
    JOIN github_workflow_run_base_manifest_origins AS origin
      ON origin.run_id = attempt.root_run_id
     AND origin.tenant_id = request.tenant_id
     AND origin.repository_id = request.repository_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = origin.tenant_id
     AND manifest.repository_id = origin.repository_id
     AND manifest.provider_connection_id = origin.provider_connection_id
     AND manifest.manifest_revision = origin.provider_manifest_revision
     AND manifest.manifest_digest = origin.provider_manifest_digest
    JOIN github_server_service_authorities AS authority
      ON authority.tenant_id = origin.tenant_id
     AND authority.id = NEW.checks_authority_id
     AND authority.repository_id = origin.repository_id
     AND authority.provider_connection_id = origin.provider_connection_id
     AND authority.provider_installation_id = origin.provider_installation_id
     AND authority.github_app_id = manifest.github_app_id
     AND authority.github_repository_id = origin.github_repository_id
     AND authority.github_repository_name = origin.github_repository_name
     AND authority.service_scope = 'checks_write'
     AND authority.github_app_client_id = manifest.github_app_client_id
     AND authority.github_app_jwt_issuer_kind =
         manifest.github_app_jwt_issuer_kind
     AND authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
     AND authority.app_configuration_revision =
         manifest.app_configuration_revision
     AND authority.policy_revision = manifest.policy_revision
     AND authority.identity_digest = NEW.checks_authority_identity_digest
     AND authority.state = 'active'
     AND authority.created_at_ms <= NEW.recorded_at_ms
     AND authority.state_updated_at_ms <= NEW.recorded_at_ms
    JOIN github_check_subjects AS source
      ON source.id = NEW.source_github_check_subject_id
     AND source.workflow_run_id = attempt.source_run_id
    JOIN github_check_subjects AS target
      ON target.id = NEW.github_check_subject_id
     AND target.workflow_run_id = attempt.run_id
    WHERE attempt.run_id = NEW.run_id
      AND attempt.source_run_id = NEW.source_run_id
      AND attempt.source_run_id IS NOT NULL
      AND request.tenant_id = NEW.tenant_id
      AND request.operation_id = NEW.operation_id
      AND request.repository_id = NEW.repository_id
      AND request.committed_at_ms = attempt.created_at_ms
      AND run.repository_id = NEW.repository_id
      AND run.status = 'queued'
      AND origin.tenant_id = NEW.tenant_id
      AND origin.repository_id = NEW.repository_id
      AND origin.provider_connection_id = NEW.provider_connection_id
      AND origin.provider_manifest_revision = NEW.provider_manifest_revision
      AND origin.provider_manifest_digest = NEW.provider_manifest_digest
      AND manifest.app_configuration_revision =
          NEW.checks_authority_app_configuration_revision
      AND manifest.policy_revision =
          NEW.checks_authority_policy_revision
      AND (
          origin.repository_visibility = 'public'
          AND origin.private_source_authority_id IS NULL
          AND NEW.private_source_authority_id IS NULL
          AND NEW.private_source_authority_identity_digest IS NULL
          AND NEW.private_source_authority_app_configuration_revision IS NULL
          AND NEW.private_source_authority_policy_revision IS NULL
          OR origin.repository_visibility = 'private'
          AND NEW.private_source_authority_id =
              origin.private_source_authority_id
          AND NEW.private_source_authority_identity_digest =
              origin.private_source_authority_identity_digest
          AND NEW.private_source_authority_app_configuration_revision =
              origin.private_source_authority_app_configuration_revision
          AND NEW.private_source_authority_policy_revision =
              origin.private_source_authority_policy_revision
          AND EXISTS (
              SELECT 1
              FROM github_server_service_authorities AS private_authority
              WHERE private_authority.tenant_id = origin.tenant_id
                AND private_authority.id =
                    origin.private_source_authority_id
                AND private_authority.repository_id = origin.repository_id
                AND private_authority.provider_connection_id =
                    origin.provider_connection_id
                AND private_authority.provider_installation_id =
                    origin.provider_installation_id
                AND private_authority.github_app_id = manifest.github_app_id
                AND private_authority.github_repository_id =
                    origin.github_repository_id
                AND private_authority.github_repository_name =
                    origin.github_repository_name
                AND private_authority.service_scope =
                    'private_repository_source_read'
                AND private_authority.github_app_client_id =
                    manifest.github_app_client_id
                AND private_authority.github_app_jwt_issuer_kind =
                    manifest.github_app_jwt_issuer_kind
                AND private_authority.app_key_spki_sha256 =
                    manifest.app_key_spki_sha256
                AND private_authority.identity_digest =
                    NEW.private_source_authority_identity_digest
                AND private_authority.app_configuration_revision =
                    NEW.private_source_authority_app_configuration_revision
                AND private_authority.policy_revision =
                    NEW.private_source_authority_policy_revision
                AND private_authority.state = 'active'
                AND private_authority.created_at_ms <= NEW.recorded_at_ms
                AND private_authority.state_updated_at_ms <= NEW.recorded_at_ms
          )
      )
      AND source.tenant_id = NEW.tenant_id
      AND source.repository_id = NEW.repository_id
      AND source.provider_connection_id = NEW.provider_connection_id
      AND source.head_sha = origin.github_check_head_sha
      AND source.provider_installation_id = origin.provider_installation_id
      AND source.github_repository_id = origin.github_repository_id
      AND source.github_repository_name = origin.github_repository_name
      AND source.github_app_id = manifest.github_app_id
      AND source.subject_key = manifest.check_subject_key
      AND source.check_name = manifest.check_name
      AND source.desired_state = 'completed'
      AND source.desired_conclusion IS NOT NULL
      AND source.terminal_cause IS NOT NULL
      AND source.desired_revision = 3
      AND target.tenant_id = source.tenant_id
      AND target.repository_id = source.repository_id
      AND target.origin_kind = 'workflow_rerun'
      AND target.provider_delivery_id IS NULL
      AND target.schedule_fire_id IS NULL
      AND target.workflow_rerun_run_id = attempt.run_id
      AND target.subject_key = source.subject_key
      AND target.provider_connection_id = source.provider_connection_id
      AND target.provider_installation_id = source.provider_installation_id
      AND target.github_repository_id = source.github_repository_id
      AND target.github_repository_name = source.github_repository_name
      AND target.github_app_id = source.github_app_id
      AND target.head_sha = source.head_sha
      AND target.head_sha = run.head_sha
      AND target.head_sha = NEW.github_check_head_sha
      AND target.check_name = source.check_name
      AND target.workflow_run_id = attempt.run_id
      AND target.linked_at_ms = attempt.created_at_ms
      AND target.desired_state = 'in_progress'
      AND target.desired_conclusion IS NULL
      AND target.terminal_cause IS NULL
      AND target.desired_revision = 2
      AND target.created_at_ms = attempt.created_at_ms
      AND target.desired_updated_at_ms = attempt.created_at_ms
      AND NEW.recorded_at_ms = attempt.created_at_ms
    FOR SHARE OF attempt, request, receipt, run, manifest, authority,
                 source, target;

    IF NEW.private_source_authority_id IS NOT NULL THEN
        SELECT TRUE INTO private_exact
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.tenant_id = NEW.tenant_id
         AND request.operation_id = NEW.operation_id
         AND request.rerun_run_id = attempt.run_id
        JOIN github_workflow_run_base_manifest_origins AS origin
          ON origin.run_id = attempt.root_run_id
         AND origin.tenant_id = request.tenant_id
         AND origin.repository_id = request.repository_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS private_authority
          ON private_authority.tenant_id = origin.tenant_id
         AND private_authority.id = NEW.private_source_authority_id
         AND private_authority.repository_id = origin.repository_id
         AND private_authority.provider_connection_id =
             origin.provider_connection_id
         AND private_authority.provider_installation_id =
             origin.provider_installation_id
         AND private_authority.github_app_id = manifest.github_app_id
         AND private_authority.github_repository_id =
             origin.github_repository_id
         AND private_authority.github_repository_name =
             origin.github_repository_name
         AND private_authority.service_scope =
             'private_repository_source_read'
         AND private_authority.github_app_client_id =
             manifest.github_app_client_id
         AND private_authority.github_app_jwt_issuer_kind =
             manifest.github_app_jwt_issuer_kind
         AND private_authority.app_key_spki_sha256 =
             manifest.app_key_spki_sha256
         AND private_authority.identity_digest =
             NEW.private_source_authority_identity_digest
         AND private_authority.app_configuration_revision =
             NEW.private_source_authority_app_configuration_revision
         AND private_authority.policy_revision =
             NEW.private_source_authority_policy_revision
         AND private_authority.state = 'active'
         AND private_authority.created_at_ms <= NEW.recorded_at_ms
         AND private_authority.state_updated_at_ms <= NEW.recorded_at_ms
        WHERE attempt.run_id = NEW.run_id
          AND origin.repository_visibility = 'private'
          AND origin.private_source_authority_id =
              NEW.private_source_authority_id
          AND origin.private_source_authority_identity_digest =
              NEW.private_source_authority_identity_digest
          AND origin.private_source_authority_app_configuration_revision =
              NEW.private_source_authority_app_configuration_revision
          AND origin.private_source_authority_policy_revision =
              NEW.private_source_authority_policy_revision
        FOR SHARE OF manifest, private_authority;
    END IF;

    IF exact IS DISTINCT FROM TRUE OR private_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow rerun Check evidence is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_check_evidence_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_rerun_check_evidence_insert_guard
BEFORE INSERT ON workflow_rerun_check_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_rerun_check_evidence();

CREATE FUNCTION automata_validate_github_workflow_rerun_subject_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    exact BOOLEAN;
BEGIN
    SELECT TRUE INTO exact
    FROM workflow_rerun_attempts AS attempt
    JOIN workflow_rerun_requests AS request
      ON request.tenant_id = NEW.tenant_id
     AND request.operation_id = NEW.operation_id
     AND request.rerun_run_id = attempt.run_id
     AND request.source_run_id = attempt.source_run_id
    JOIN workflow_admission_receipts AS receipt
      ON receipt.tenant_id = request.tenant_id
     AND receipt.idempotency_kind = 'operation'
     AND receipt.idempotency_key =
         'workflow-rerun:' || request.operation_id::TEXT
     AND receipt.request_digest = request.request_digest
     AND receipt.repository_id = request.repository_id
     AND receipt.run_id = attempt.run_id
     AND receipt.committed_at_ms = attempt.created_at_ms
     AND receipt.github_subject_evidence_required
    JOIN workflow_runs AS run
      ON run.id = attempt.run_id
     AND run.repository_id = request.repository_id
    JOIN workflow_definitions AS workflow
      ON workflow.repository_id = run.repository_id
     AND workflow.id = run.workflow_id
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
    JOIN workflow_rerun_check_evidence AS check_evidence
      ON check_evidence.tenant_id = request.tenant_id
     AND check_evidence.operation_id = request.operation_id
     AND check_evidence.run_id = attempt.run_id
     AND check_evidence.source_run_id = attempt.source_run_id
    JOIN github_check_subjects AS subject
      ON subject.tenant_id = check_evidence.tenant_id
     AND subject.id = check_evidence.github_check_subject_id
     AND subject.workflow_rerun_run_id = check_evidence.run_id
    JOIN github_workflow_run_base_manifest_origins AS origin
      ON origin.tenant_id = request.tenant_id
     AND origin.repository_id = request.repository_id
     AND origin.run_id = attempt.root_run_id
     AND origin.provider_connection_id = check_evidence.provider_connection_id
     AND origin.provider_manifest_revision =
         check_evidence.provider_manifest_revision
     AND origin.provider_manifest_digest = check_evidence.provider_manifest_digest
    WHERE attempt.run_id = NEW.run_id
      AND attempt.source_run_id = NEW.source_run_id
      AND attempt.source_run_id IS NOT NULL
      AND request.repository_id = NEW.repository_id
      AND request.committed_at_ms = NEW.admitted_at_ms
      AND request.committed_at_ms = attempt.created_at_ms
      AND run.workflow_id = NEW.workflow_id
      AND run.snapshot_id = NEW.snapshot_id
      AND run.head_sha = NEW.github_check_head_sha
      AND run.event_name = NEW.event_name
      AND run.event_digest = NEW.event_digest
      AND run.git_ref = NEW.git_ref
      AND run.plan_schema = NEW.workflow_plan_schema
      AND run.plan_digest = NEW.plan_digest
      AND run.created_at_ms = NEW.admitted_at_ms
      AND run.status = 'queued'
      AND workflow.path = NEW.workflow_path
      AND snapshot.source_digest = NEW.source_digest
      AND marker.root_invocation_id = NEW.root_invocation_id
      AND marker.admission_digest = NEW.logical_admission_digest
      AND marker.admitted_at_ms = NEW.admitted_at_ms
      AND check_evidence.github_check_subject_id =
          NEW.github_check_subject_id
      AND check_evidence.github_check_head_sha = NEW.github_check_head_sha
      AND check_evidence.recorded_at_ms = NEW.admitted_at_ms
      AND subject.workflow_run_id = run.id
      AND subject.linked_at_ms = NEW.admitted_at_ms
      AND subject.desired_state = 'in_progress'
      AND subject.desired_conclusion IS NULL
      AND subject.terminal_cause IS NULL
      AND subject.desired_revision = 2
      AND subject.desired_updated_at_ms = NEW.admitted_at_ms
      AND origin.github_check_head_sha = NEW.github_check_head_sha
      AND origin.github_repository_owner_id =
          NEW.github_repository_owner_id
      AND origin.workflow_path = NEW.workflow_path
      AND origin.source_digest = NEW.source_digest
      AND origin.event_name = NEW.event_name
      AND origin.event_digest = NEW.event_digest
      AND origin.git_ref = NEW.git_ref
      AND origin.workflow_plan_schema = NEW.workflow_plan_schema
      AND origin.plan_digest = NEW.plan_digest
    FOR KEY SHARE OF attempt, request, receipt, run, workflow, snapshot,
                     marker, check_evidence, subject;

    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'GitHub workflow rerun run-subject evidence is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_rerun_subject_evidence_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_workflow_rerun_subject_evidence_00_insert_guard
BEFORE INSERT ON github_workflow_rerun_subject_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_validate_github_workflow_rerun_subject_evidence();

CREATE FUNCTION automata_workflow_rerun_check_requires_atomic_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    durable github_check_subjects%ROWTYPE;
    evidence workflow_rerun_check_evidence%ROWTYPE;
    run_evidence github_workflow_rerun_subject_evidence%ROWTYPE;
    outbox github_check_projection_outbox%ROWTYPE;
BEGIN
    IF NEW.origin_kind <> 'workflow_rerun' THEN
        RETURN NULL;
    END IF;
    SELECT * INTO durable
    FROM github_check_subjects
    WHERE id = NEW.id;
    SELECT * INTO evidence
    FROM workflow_rerun_check_evidence
    WHERE run_id = NEW.workflow_rerun_run_id
      AND github_check_subject_id = NEW.id;
    SELECT * INTO run_evidence
    FROM github_workflow_rerun_subject_evidence
    WHERE tenant_id = NEW.tenant_id
      AND run_id = NEW.workflow_rerun_run_id
      AND github_check_subject_id = NEW.id;
    SELECT * INTO outbox
    FROM github_check_projection_outbox
    WHERE subject_id = NEW.id;
    IF durable.id IS NULL
        OR durable.workflow_run_id <> NEW.workflow_rerun_run_id
        OR durable.linked_at_ms <> durable.created_at_ms
        OR durable.desired_state <> 'in_progress'
        OR durable.desired_conclusion IS NOT NULL
        OR durable.terminal_cause IS NOT NULL
        OR durable.desired_revision <> 2
        OR durable.desired_updated_at_ms <> durable.created_at_ms
        OR evidence.run_id IS NULL
        OR evidence.recorded_at_ms <> durable.created_at_ms
        OR run_evidence.run_id IS NULL
        OR run_evidence.github_check_head_sha <> durable.head_sha
        OR run_evidence.admitted_at_ms <> durable.created_at_ms
        OR octet_length(run_evidence.subject_evidence_sha256) <> 32
        OR outbox.subject_id IS NULL
        OR outbox.state <> 'pending'
        OR outbox.attempted_revision IS NOT NULL
        OR outbox.attempt_count <> 0
        OR outbox.claim_fence <> 0
        OR outbox.projected_revision <> 0
        OR outbox.state_updated_at_ms <> durable.created_at_ms
    THEN
        RAISE EXCEPTION 'workflow rerun Check requires atomic evidence and outbox'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_check_atomic_evidence_required';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER github_check_subjects_require_atomic_rerun_evidence
AFTER INSERT ON github_check_subjects
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_workflow_rerun_check_requires_atomic_evidence();

CREATE FUNCTION automata_workflow_rerun_link_requires_run_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    evidence github_workflow_rerun_subject_evidence%ROWTYPE;
BEGIN
    IF NEW.origin_kind <> 'workflow_rerun'
        OR OLD.workflow_run_id IS NOT NULL
        OR NEW.workflow_run_id IS NULL
    THEN
        RETURN NULL;
    END IF;
    SELECT * INTO evidence
    FROM github_workflow_rerun_subject_evidence
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND run_id = NEW.workflow_run_id
      AND github_check_subject_id = NEW.id;
    IF evidence.run_id IS NULL
        OR NEW.workflow_run_id <> NEW.workflow_rerun_run_id
        OR NEW.linked_at_ms <> evidence.admitted_at_ms
        OR NEW.desired_state <> 'in_progress'
        OR NEW.desired_conclusion IS NOT NULL
        OR NEW.terminal_cause IS NOT NULL
        OR NEW.desired_revision <> 2
        OR NEW.desired_updated_at_ms <> evidence.admitted_at_ms
        OR NEW.head_sha <> evidence.github_check_head_sha
    THEN
        RAISE EXCEPTION 'workflow rerun Check link requires exact run evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_check_link_evidence_required';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER github_check_subjects_require_rerun_link_evidence
AFTER UPDATE OF workflow_run_id, linked_at_ms, desired_state,
                desired_revision, desired_updated_at_ms
ON github_check_subjects
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_workflow_rerun_link_requires_run_evidence();

CREATE OR REPLACE VIEW github_workflow_run_manifest_origins AS
SELECT * FROM github_workflow_run_base_manifest_origins
UNION ALL
SELECT origin.tenant_id,
       origin.repository_id,
       rerun.workflow_id,
       rerun.snapshot_id,
       attempt.run_id,
       marker.root_invocation_id,
       'workflow_rerun'::TEXT AS origin_kind,
       request.operation_id AS origin_id,
       'operation'::TEXT AS admission_idempotency_kind,
       ('workflow-rerun:' || request.operation_id::TEXT)::TEXT
           AS admission_idempotency_key,
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
       check_evidence.private_source_authority_id,
       check_evidence.private_source_authority_identity_digest,
       check_evidence.private_source_authority_app_configuration_revision,
       check_evidence.private_source_authority_policy_revision
FROM workflow_rerun_attempts AS attempt
JOIN workflow_rerun_check_evidence AS check_evidence
  ON check_evidence.run_id = attempt.run_id
 AND check_evidence.source_run_id = attempt.source_run_id
JOIN workflow_rerun_requests AS request
  ON request.tenant_id = check_evidence.tenant_id
 AND request.operation_id = check_evidence.operation_id
 AND request.rerun_run_id = attempt.run_id
 AND request.committed_at_ms = attempt.created_at_ms
JOIN workflow_runs AS rerun ON rerun.id = attempt.run_id
JOIN workflow_plan_v2_runs AS marker ON marker.run_id = attempt.run_id
JOIN github_workflow_rerun_subject_evidence AS run_evidence
  ON run_evidence.tenant_id = check_evidence.tenant_id
 AND run_evidence.operation_id = check_evidence.operation_id
 AND run_evidence.run_id = check_evidence.run_id
 AND run_evidence.source_run_id = check_evidence.source_run_id
 AND run_evidence.github_check_subject_id =
     check_evidence.github_check_subject_id
 AND run_evidence.github_check_head_sha =
     check_evidence.github_check_head_sha
 AND run_evidence.admitted_at_ms = check_evidence.recorded_at_ms
JOIN github_workflow_run_base_manifest_origins AS origin
  ON origin.run_id = attempt.root_run_id
 AND origin.tenant_id = check_evidence.tenant_id
 AND origin.repository_id = check_evidence.repository_id
 AND origin.provider_connection_id = check_evidence.provider_connection_id
 AND origin.provider_manifest_revision =
     check_evidence.provider_manifest_revision
 AND origin.provider_manifest_digest = check_evidence.provider_manifest_digest
WHERE attempt.source_run_id IS NOT NULL;

-- Runner-policy preparation must bind to the immutable run origin rather than
-- a webhook-delivery-only table.  The common origin retains the exact
-- admission receipt and historical manifest tuple for deliveries, schedules,
-- and reruns.
CREATE OR REPLACE FUNCTION automata_require_preparation_runner_policy_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.runner_policy_digest IS DISTINCT FROM OLD.runner_policy_digest
            OR NEW.runner_policy_object_key IS DISTINCT FROM OLD.runner_policy_object_key
            OR NEW.runner_policy_size_bytes IS DISTINCT FROM OLD.runner_policy_size_bytes
            OR NEW.runner_policy_media_type IS DISTINCT FROM OLD.runner_policy_media_type
        THEN
            RAISE EXCEPTION 'logical preparation runner policy is immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_runner_policy_immutable';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_plan_v2_jobs AS job
    JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = job.run_id
    JOIN github_workflow_run_manifest_origins AS origin
      ON origin.run_id = job.run_id
     AND origin.tenant_id = pin.tenant_id
     AND origin.repository_id = pin.repository_id
    JOIN workflow_admission_receipts AS receipt
      ON receipt.tenant_id = origin.tenant_id
     AND receipt.idempotency_kind = origin.admission_idempotency_kind
     AND receipt.idempotency_key = origin.admission_idempotency_key
     AND receipt.repository_id = origin.repository_id
     AND receipt.run_id = origin.run_id
     AND receipt.request_digest = origin.logical_admission_digest
     AND receipt.committed_at_ms = origin.admitted_at_ms
     AND receipt.github_subject_evidence_required
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = origin.tenant_id
     AND manifest.repository_id = origin.repository_id
     AND manifest.provider_connection_id = origin.provider_connection_id
     AND manifest.manifest_revision = origin.provider_manifest_revision
     AND manifest.manifest_digest = origin.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = pin.tenant_id
     AND policy.repository_id = pin.repository_id
     AND policy.policy_revision = pin.policy_revision
     AND policy.policy_digest = pin.policy_digest
     AND policy.state = 'sealed'
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
      AND NEW.runtime_policy_revision = pin.policy_revision
      AND NEW.runtime_policy_digest = pin.policy_digest
      AND manifest.runtime_policy_revision = pin.policy_revision
      AND manifest.runtime_policy_digest = pin.policy_digest
      AND NEW.runner_policy_digest = manifest.runner_policy_digest
      AND NEW.runner_policy_object_key = manifest.runner_policy_object_key
      AND NEW.runner_policy_size_bytes = manifest.runner_policy_size_bytes
      AND NEW.runner_policy_media_type = manifest.runner_policy_media_type
      AND NEW.runner_policy_digest = pg_catalog.sha256(policy.canonical_policy)
      AND NEW.runner_policy_size_bytes = pg_catalog.octet_length(policy.canonical_policy)
    FOR KEY SHARE OF job, pin, receipt, manifest, policy;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'logical preparation runner policy lacks authenticated manifest provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_runner_policy_provenance';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Activation preparation must consume the same immutable manifest origin as
-- admission. Earlier revisions joined webhook evidence directly, which made
-- scheduled and rerun attempts fail after their graph had been admitted.
CREATE OR REPLACE FUNCTION automata_validate_activation_preparation_authority_profile()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN github_workflow_run_manifest_origins AS origin
          ON origin.tenant_id = repository.tenant_id
         AND origin.repository_id = run.repository_id
         AND origin.run_id = run.id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        WHERE run.id = NEW.run_id
          AND automata_workflow_plan_v2_invocation_published(
              run.id, NEW.invocation_id
          )
          AND manifest.authority_profile = NEW.authority_profile
    ) THEN
        RAISE EXCEPTION 'logical activation preparation lacks exact historical authority profile'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_activation_preparation_historical_profile';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Preparation claims use the same effective terminal-result boundary as the
-- readiness scan.  A carried result is immutable evidence from the selected
-- attempt's source graph; requiring a fresh result claim here would make an
-- otherwise-ready partial rerun impossible to claim.
CREATE OR REPLACE FUNCTION automata_validate_logical_activation_preparation_claim()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    expected_count BIGINT;
    finalized_count BIGINT;
    latest_ready BIGINT;
    expected_status TEXT;
BEGIN
    SELECT count(dependency.prerequisite_job_id),
           count(result.logical_job_id),
           greatest(job.created_at_ms, coalesce(max(result.finalized_at_ms), 0)),
           CASE
               WHEN coalesce(bool_or(
                   result.closure_has_failure
                   OR result.effective_conclusion IN ('failure', 'timed_out')
               ), FALSE) THEN 'failure'
               WHEN coalesce(bool_or(
                   result.closure_has_cancelled
                   OR result.effective_conclusion = 'cancelled'
               ), FALSE) THEN 'cancelled'
               WHEN coalesce(bool_or(
                   result.closure_has_skipped
                   OR result.effective_conclusion = 'skipped'
               ), FALSE) THEN 'skipped'
               ELSE 'success'
           END
      INTO expected_count, finalized_count, latest_ready, expected_status
    FROM workflow_plan_v2_jobs AS job
    JOIN workflow_plan_v2_invocations AS invocation
      ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    LEFT JOIN workflow_plan_v2_dependencies AS dependency
      ON dependency.run_id = job.run_id
     AND dependency.invocation_id = job.invocation_id
     AND dependency.logical_job_id = job.id
    LEFT JOIN workflow_plan_v2_effective_job_results AS result
      ON result.run_id = dependency.run_id
     AND result.invocation_id = dependency.invocation_id
     AND result.logical_job_id = dependency.prerequisite_job_id
     AND result.claim_state = 'finalized'
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
      AND job.logical_key = NEW.logical_key
      AND job.source_order = NEW.source_order
      AND job.execution_kind = 'steps'
      AND job.state = 'pending'
      AND automata_workflow_plan_v2_invocation_published(
          marker.run_id, invocation.id
      )
      AND invocation.plan_digest = NEW.plan_digest
      AND invocation.plan_object_key = NEW.plan_object_key
      AND invocation.plan_size_bytes = NEW.plan_size_bytes
      AND invocation.plan_media_type = NEW.plan_media_type
      AND invocation.plan_schema = NEW.plan_schema
      AND invocation.state IN ('pending', 'active')
      AND marker.orchestration_schema = 1
      AND marker.state IN ('pending', 'active')
      AND run.admission_epoch = 4
      AND run.plan_schema = 2
      AND run.workflow_id = NEW.workflow_id
      AND run.workflow_name = NEW.workflow_name
      AND run.git_ref = NEW.git_ref
      AND run.actor IS NOT DISTINCT FROM NEW.actor
      AND run.run_number = NEW.run_number
      AND run.run_attempt = NEW.run_attempt
      AND run.event_digest = NEW.event_digest
      AND run.event_object_key = NEW.event_object_key
      AND run.event_size_bytes = NEW.event_size_bytes
      AND run.event_media_type = NEW.event_media_type
    GROUP BY job.created_at_ms;

    IF NOT FOUND
        OR expected_count <> finalized_count
        OR expected_count <> NEW.prerequisite_count
        OR latest_ready <> NEW.evidence_ready_at_ms
        OR expected_status <> NEW.aggregate_status
        OR NEW.claimed_at_ms < latest_ready
        OR NEW.created_at_ms <> NEW.claimed_at_ms
    THEN
        RAISE EXCEPTION 'logical activation preparation claim lacks exact current evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

-- The deferred evidence seal and root graph window consume the same closed
-- manifest-origin projection for deliveries, schedules, and reruns.
CREATE OR REPLACE FUNCTION automata_required_github_subject_evidence_committed()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    receipt workflow_admission_receipts%ROWTYPE;
    evidence_count BIGINT;
BEGIN
    IF NOT NEW.github_subject_evidence_required THEN
        RETURN NULL;
    END IF;

    SELECT * INTO receipt
    FROM workflow_admission_receipts
    WHERE tenant_id = NEW.tenant_id
      AND idempotency_kind = NEW.idempotency_kind
      AND idempotency_key = NEW.idempotency_key;

    IF receipt.github_subject_evidence_required
        AND receipt.idempotency_kind = 'provider_delivery'
        AND receipt.repository_id IS NOT NULL
        AND receipt.run_id IS NOT NULL
        AND receipt.committed_at_ms IS NOT NULL
    THEN
        SELECT count(*) INTO evidence_count
        FROM github_workflow_run_subject_evidence AS evidence
        WHERE evidence.tenant_id = receipt.tenant_id
          AND evidence.repository_id = receipt.repository_id
          AND evidence.run_id = receipt.run_id
          AND evidence.provider_delivery_idempotency_key = receipt.idempotency_key
          AND evidence.logical_admission_digest = receipt.request_digest
          AND evidence.admitted_at_ms = receipt.committed_at_ms;
    ELSIF receipt.github_subject_evidence_required
        AND receipt.idempotency_kind = 'operation'
        AND receipt.idempotency_key LIKE 'workflow-rerun:%'
        AND receipt.repository_id IS NOT NULL
        AND receipt.run_id IS NOT NULL
        AND receipt.committed_at_ms IS NOT NULL
    THEN
        SELECT count(*) INTO evidence_count
        FROM github_workflow_rerun_subject_evidence AS evidence
        WHERE evidence.tenant_id = receipt.tenant_id
          AND evidence.repository_id = receipt.repository_id
          AND evidence.run_id = receipt.run_id
          AND 'workflow-rerun:' || evidence.operation_id::TEXT =
              receipt.idempotency_key
          AND evidence.logical_admission_digest = receipt.request_digest
          AND evidence.admitted_at_ms = receipt.committed_at_ms;
    ELSIF receipt.github_subject_evidence_required
        AND receipt.idempotency_kind = 'operation'
        AND receipt.repository_id IS NOT NULL
        AND receipt.run_id IS NOT NULL
        AND receipt.committed_at_ms IS NOT NULL
    THEN
        SELECT count(*) INTO evidence_count
        FROM github_schedule_workflow_run_subject_evidence AS evidence
        WHERE evidence.tenant_id = receipt.tenant_id
          AND evidence.repository_id = receipt.repository_id
          AND evidence.run_id = receipt.run_id
          AND evidence.schedule_fire_id::TEXT = receipt.idempotency_key
          AND evidence.logical_admission_digest = receipt.request_digest
          AND evidence.admitted_at_ms = receipt.committed_at_ms;
    END IF;

    IF evidence_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'authenticated GitHub admission requires exact subject evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_admission_required_github_evidence_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_require_open_workflow_admission_graph()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN github_workflow_run_manifest_origins AS origin
      ON origin.run_id = marker.run_id
     AND origin.root_invocation_id = marker.root_invocation_id
    JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND receipt.idempotency_kind = origin.admission_idempotency_kind
      AND receipt.idempotency_key = origin.admission_idempotency_key
      AND receipt.request_digest = marker.admission_digest
      AND origin.logical_admission_digest = marker.admission_digest
      AND origin.admitted_at_ms = receipt.committed_at_ms
      AND pin.pinned_at_ms = origin.admitted_at_ms
    FOR KEY SHARE OF marker, receipt, pin;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    JOIN security_audit_events AS audit
      ON audit.tenant_id = pin.tenant_id
     AND audit.action = 'workflow.dispatch'
     AND audit.outcome = 'succeeded'
     AND audit.resource_kind = 'workflow_run'
     AND audit.resource_id = marker.run_id::TEXT
     AND audit.occurred_at_ms = pin.pinned_at_ms
     AND audit.actor_kind = 'human'
     AND audit.actor_principal_id IS NOT NULL
     AND audit.actor_session_id IS NOT NULL
     AND audit.authorization_revision IS NOT NULL
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND receipt.github_subject_evidence_required = FALSE
      AND receipt.request_digest = marker.admission_digest
      AND pin.pinned_at_ms = receipt.committed_at_ms
    FOR KEY SHARE OF marker, receipt, pin, audit;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_plan_v2_reusable_call_publications AS publication
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = publication.run_id
    WHERE publication.run_id = NEW.run_id
      AND publication.child_invocation_id = NEW.invocation_id
      AND publication.child_graph_sealed_at_ms IS NULL
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND marker.state IN ('pending', 'active')
      AND NOT EXISTS (
          SELECT 1 FROM workflow_plan_v2_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR KEY SHARE OF publication, marker;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow graph insertion is outside an authenticated publication window'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_admission_graph_construction_window';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Selected jobs consume carried prerequisites through the effective result
-- boundary.  The original result/claim pair and the carried row are both
-- immutable, and the latter is foreign-keyed to the source run aggregate.
CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_job_result_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.invocation_id = job.invocation_id
         AND publication.logical_job_id = job.id
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'steps'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_schema = 2
          AND invocation.plan_media_type =
              'application/vnd.automata.workflow-plan+json'
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND NEW.claimed_at_ms >= publication.published_at_ms
          AND (
              (publication.instance_count = 0 AND NOT EXISTS (
                  SELECT 1 FROM workflow_plan_v2_instances AS instance
                  WHERE instance.run_id = job.run_id
                    AND instance.invocation_id = job.invocation_id
                    AND instance.logical_job_id = job.id
              )) OR (
                  publication.instance_count > 0
                  AND publication.instance_count = (
                      SELECT count(*)
                      FROM workflow_plan_v2_instances AS instance
                      JOIN workflow_plan_v2_instance_results AS result
                        ON result.instance_id = instance.id
                       AND result.run_id = instance.run_id
                       AND result.invocation_id = instance.invocation_id
                       AND result.logical_job_id = instance.logical_job_id
                      JOIN workflow_plan_v2_instance_result_claims AS claim
                        ON claim.instance_id = result.instance_id
                       AND claim.state = 'finalized'
                      WHERE instance.run_id = job.run_id
                        AND instance.invocation_id = job.invocation_id
                        AND instance.logical_job_id = job.id
                  )
                  AND NEW.claimed_at_ms >= COALESCE((
                      SELECT max(result.finalized_at_ms)
                      FROM workflow_plan_v2_instance_results AS result
                      WHERE result.run_id = job.run_id
                        AND result.invocation_id = job.invocation_id
                        AND result.logical_job_id = job.id
                  ), 0)
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_dependencies AS dependency
              LEFT JOIN workflow_plan_v2_effective_job_results AS prerequisite
                ON prerequisite.logical_job_id = dependency.prerequisite_job_id
               AND prerequisite.run_id = dependency.run_id
               AND prerequisite.invocation_id = dependency.invocation_id
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
                AND (prerequisite.logical_job_id IS NULL
                     OR prerequisite.claim_state IS DISTINCT FROM 'finalized'
                     OR NEW.claimed_at_ms < prerequisite.finalized_at_ms)
          )
    ) AND NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN workflow_plan_v2_reusable_call_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.parent_invocation_id = job.invocation_id
         AND publication.caller_logical_job_id = job.id
        JOIN workflow_plan_v2_reusable_call_results AS call_result
          ON call_result.run_id = publication.run_id
         AND call_result.parent_invocation_id = publication.parent_invocation_id
         AND call_result.caller_logical_job_id = publication.caller_logical_job_id
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'reusable_workflow'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_schema = 2
          AND invocation.plan_media_type =
              'application/vnd.automata.workflow-plan+json'
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND publication.child_graph_sealed_at_ms IS NOT NULL
          AND call_result.sealed_at_ms IS NOT NULL
          AND call_result.parent_result_descriptor_digest = NEW.descriptor_digest
          AND NEW.claimed_at_ms >= call_result.completed_at_ms
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_dependencies AS dependency
              LEFT JOIN workflow_plan_v2_effective_job_results AS prerequisite
                ON prerequisite.logical_job_id = dependency.prerequisite_job_id
               AND prerequisite.run_id = dependency.run_id
               AND prerequisite.invocation_id = dependency.invocation_id
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
                AND (prerequisite.logical_job_id IS NULL
                     OR prerequisite.claim_state IS DISTINCT FROM 'finalized'
                     OR NEW.claimed_at_ms < prerequisite.finalized_at_ms)
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 job-result claim is not exactly ready'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_run_result_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state <> 'aggregating' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE marker.run_id = NEW.run_id
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND marker.revision < 9223372036854775807
          AND invocation.plan_schema = 2
          AND invocation.state IN ('pending', 'active')
          AND invocation.revision < 9223372036854775807
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND run.status IN ('queued', 'in_progress', 'cancelled')
          AND NEW.claimed_at_ms >= greatest(
              marker.updated_at_ms,
              invocation.updated_at_ms,
              run.updated_at_ms,
              COALESCE((
                  SELECT max(result.finalized_at_ms)
                  FROM workflow_plan_v2_effective_job_results AS result
                  WHERE result.run_id = marker.run_id
                    AND result.invocation_id = marker.root_invocation_id
              ), 0)
          )
          AND (SELECT count(*)
               FROM workflow_plan_v2_jobs AS job
               WHERE job.run_id = marker.run_id
                 AND job.invocation_id = marker.root_invocation_id)
              BETWEEN 1 AND 1024
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_jobs AS job
              LEFT JOIN workflow_plan_v2_effective_job_results AS result
                ON result.run_id = job.run_id
               AND result.invocation_id = job.invocation_id
               AND result.logical_job_id = job.id
              WHERE job.run_id = marker.run_id
                AND job.invocation_id = marker.root_invocation_id
                AND (
                    result.logical_job_id IS NULL
                    OR result.claim_state IS DISTINCT FROM 'finalized'
                    OR result.logical_key IS DISTINCT FROM job.logical_key
                    OR result.source_order IS DISTINCT FROM job.source_order
                    OR job.state IS DISTINCT FROM CASE result.effective_conclusion
                        WHEN 'success' THEN 'completed'
                        WHEN 'failure' THEN 'failed'
                        WHEN 'timed_out' THEN 'failed'
                        WHEN 'cancelled' THEN 'cancelled'
                        WHEN 'skipped' THEN 'skipped'
                    END
                    OR result.prerequisite_count IS DISTINCT FROM (
                        SELECT count(*)::INTEGER
                        FROM workflow_plan_v2_dependencies AS dependency
                        WHERE dependency.run_id = job.run_id
                          AND dependency.invocation_id = job.invocation_id
                          AND dependency.logical_job_id = job.id
                    )
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM (
                  SELECT job.source_order,
                         row_number() OVER (ORDER BY job.source_order) - 1 AS expected_order
                  FROM workflow_plan_v2_jobs AS job
                  WHERE job.run_id = marker.run_id
                    AND job.invocation_id = marker.root_invocation_id
              ) AS ordered
              WHERE ordered.source_order <> ordered.expected_order
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run-result claim is not exactly ready'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_enforce_workflow_plan_v2_run_result_claim_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.root_invocation_id IS DISTINCT FROM OLD.root_invocation_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run-result claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'aggregating' AND NEW.state = 'aggregating' THEN
        IF NEW.generation <> OLD.generation + 1
            OR NEW.claimed_at_ms < OLD.expires_at_ms
            OR NEW.expires_at_ms <= NEW.claimed_at_ms
            OR NEW.expires_at_ms - NEW.claimed_at_ms > 900000
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 run-result takeover is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'aggregating' AND NEW.state = 'finalized' THEN
        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NOT EXISTS (
                SELECT 1
                FROM workflow_plan_v2_run_results AS result
                JOIN workflow_plan_v2_invocations AS invocation
                  ON invocation.run_id = result.run_id
                 AND invocation.id = result.root_invocation_id
                JOIN workflow_plan_v2_runs AS marker ON marker.run_id = result.run_id
                JOIN workflow_runs AS run ON run.id = result.run_id
                WHERE result.run_id = NEW.run_id
                  AND result.root_invocation_id = NEW.root_invocation_id
                  AND result.descriptor_digest = NEW.descriptor_digest
                  AND result.claim_owner_id = OLD.owner_id
                  AND result.claim_generation = OLD.generation
                  AND result.claim_started_at_ms = OLD.claimed_at_ms
                  AND result.claim_expires_at_ms = OLD.expires_at_ms
                  AND result.finalized_at_ms = NEW.updated_at_ms
                  AND result.job_count = (
                      SELECT count(*)::INTEGER
                      FROM workflow_plan_v2_run_result_jobs AS evidence
                      WHERE evidence.run_id = result.run_id
                  )
                  AND result.job_count = (
                      SELECT count(*)::INTEGER
                      FROM workflow_plan_v2_jobs AS job
                      WHERE job.run_id = result.run_id
                        AND job.invocation_id = result.root_invocation_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM workflow_plan_v2_jobs AS job
                      LEFT JOIN workflow_plan_v2_run_result_jobs AS evidence
                        ON evidence.run_id = job.run_id
                       AND evidence.root_invocation_id = job.invocation_id
                       AND evidence.logical_job_id = job.id
                      LEFT JOIN workflow_plan_v2_effective_job_results AS logical_result
                        ON logical_result.run_id = job.run_id
                       AND logical_result.invocation_id = job.invocation_id
                       AND logical_result.logical_job_id = job.id
                      WHERE job.run_id = result.run_id
                        AND job.invocation_id = result.root_invocation_id
                        AND (
                            evidence.logical_job_id IS NULL
                            OR logical_result.logical_job_id IS NULL
                            OR logical_result.claim_state IS DISTINCT FROM 'finalized'
                            OR evidence.logical_key IS DISTINCT FROM job.logical_key
                            OR evidence.source_order IS DISTINCT FROM job.source_order
                            OR evidence.descriptor_digest IS DISTINCT FROM logical_result.descriptor_digest
                            OR evidence.effective_conclusion IS DISTINCT FROM logical_result.effective_conclusion
                            OR evidence.closure_has_failure IS DISTINCT FROM logical_result.closure_has_failure
                            OR evidence.closure_has_cancelled IS DISTINCT FROM logical_result.closure_has_cancelled
                            OR evidence.closure_has_skipped IS DISTINCT FROM logical_result.closure_has_skipped
                            OR evidence.instance_count IS DISTINCT FROM logical_result.instance_count
                            OR evidence.instances_digest IS DISTINCT FROM logical_result.instances_digest
                            OR evidence.prerequisite_count IS DISTINCT FROM logical_result.prerequisite_count
                            OR evidence.prerequisites_digest IS DISTINCT FROM logical_result.prerequisites_digest
                            OR evidence.output_count IS DISTINCT FROM logical_result.output_count
                            OR evidence.outputs_digest IS DISTINCT FROM logical_result.outputs_digest
                            OR evidence.job_commit_digest IS DISTINCT FROM logical_result.commit_digest
                            OR evidence.job_finalized_at_ms IS DISTINCT FROM logical_result.finalized_at_ms
                        )
                  )
                  AND result.effective_conclusion = CASE
                      WHEN result.workflow_status = 'cancelled' THEN 'cancelled'
                      WHEN EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'failure'
                      ) THEN 'failure'
                      WHEN EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'timed_out'
                      ) THEN 'timed_out'
                      WHEN EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'cancelled'
                      ) THEN 'cancelled'
                      WHEN NOT EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion <> 'skipped'
                      ) THEN 'skipped'
                      ELSE 'success'
                  END
                  AND invocation.state = CASE result.effective_conclusion
                      WHEN 'success' THEN 'completed'
                      WHEN 'skipped' THEN 'completed'
                      WHEN 'cancelled' THEN 'cancelled'
                      ELSE 'failed'
                  END
                  AND invocation.revision = result.invocation_revision + 1
                  AND invocation.updated_at_ms = result.finalized_at_ms
                  AND marker.state = CASE result.effective_conclusion
                      WHEN 'success' THEN 'completed'
                      WHEN 'skipped' THEN 'completed'
                      WHEN 'cancelled' THEN 'cancelled'
                      ELSE 'failed'
                  END
                  AND marker.revision = result.marker_revision + 1
                  AND marker.updated_at_ms = result.finalized_at_ms
                  AND run.status = CASE result.effective_conclusion
                      WHEN 'cancelled' THEN 'cancelled'
                      ELSE 'completed'
                  END
                  AND run.updated_at_ms = result.finalized_at_ms
            )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 run-result finalization lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'WorkflowPlan-v2 run-result claim transition is invalid'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_run_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_run_result_claims AS claim
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = claim.run_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE claim.run_id = NEW.run_id
          AND claim.root_invocation_id = NEW.root_invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.admission_digest = NEW.admission_digest
          AND marker.state = NEW.marker_state
          AND marker.revision = NEW.marker_revision
          AND marker.updated_at_ms = NEW.marker_updated_at_ms
          AND invocation.state = NEW.invocation_state
          AND invocation.revision = NEW.invocation_revision
          AND invocation.updated_at_ms = NEW.invocation_updated_at_ms
          AND run.status = NEW.workflow_status
          AND run.updated_at_ms = NEW.workflow_updated_at_ms
          AND NEW.job_count = (
              SELECT count(*)::INTEGER
              FROM workflow_plan_v2_jobs AS job
              WHERE job.run_id = NEW.run_id
                AND job.invocation_id = NEW.root_invocation_id
          )
          AND NEW.finalized_at_ms >= greatest(
              NEW.marker_updated_at_ms,
              NEW.invocation_updated_at_ms,
              NEW.workflow_updated_at_ms,
              COALESCE((
                  SELECT max(result.finalized_at_ms)
                  FROM workflow_plan_v2_effective_job_results AS result
                  WHERE result.run_id = NEW.run_id
                    AND result.invocation_id = NEW.root_invocation_id
              ), 0)
          )
          AND NEW.finalized_at_ms < claim.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run result lacks exact descriptor/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_run_result_job()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_run_results AS run_result
        JOIN workflow_plan_v2_run_result_claims AS run_claim
          ON run_claim.run_id = run_result.run_id
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = run_result.run_id
         AND job.invocation_id = run_result.root_invocation_id
         AND job.id = NEW.logical_job_id
        JOIN workflow_plan_v2_effective_job_results AS logical_result
          ON logical_result.run_id = job.run_id
         AND logical_result.invocation_id = job.invocation_id
         AND logical_result.logical_job_id = job.id
        WHERE run_result.run_id = NEW.run_id
          AND run_result.root_invocation_id = NEW.root_invocation_id
          AND run_claim.state = 'aggregating'
          AND job.logical_key = NEW.logical_key
          AND job.source_order = NEW.source_order
          AND logical_result.claim_state = 'finalized'
          AND logical_result.descriptor_digest = NEW.descriptor_digest
          AND logical_result.effective_conclusion = NEW.effective_conclusion
          AND logical_result.closure_has_failure = NEW.closure_has_failure
          AND logical_result.closure_has_cancelled = NEW.closure_has_cancelled
          AND logical_result.closure_has_skipped = NEW.closure_has_skipped
          AND logical_result.instance_count = NEW.instance_count
          AND logical_result.instances_digest = NEW.instances_digest
          AND logical_result.prerequisite_count = NEW.prerequisite_count
          AND logical_result.prerequisites_digest = NEW.prerequisites_digest
          AND logical_result.output_count = NEW.output_count
          AND logical_result.outputs_digest = NEW.outputs_digest
          AND logical_result.commit_digest = NEW.job_commit_digest
          AND logical_result.finalized_at_ms = NEW.job_finalized_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run-result job evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Carried prerequisites are finalized effective results even though they do
-- not manufacture a fresh job-result claim in the new physical attempt.
CREATE OR REPLACE FUNCTION automata_validate_logical_activation_preparation_prerequisite()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_preparation_claims AS claim
        JOIN workflow_plan_v2_dependencies AS dependency
          ON dependency.run_id = claim.run_id
         AND dependency.invocation_id = claim.invocation_id
         AND dependency.logical_job_id = claim.logical_job_id
         AND dependency.prerequisite_job_id = NEW.prerequisite_job_id
        JOIN workflow_plan_v2_jobs AS prerequisite_job
          ON prerequisite_job.run_id = dependency.run_id
         AND prerequisite_job.invocation_id = dependency.invocation_id
         AND prerequisite_job.id = dependency.prerequisite_job_id
        JOIN workflow_plan_v2_effective_job_results AS result
          ON result.run_id = dependency.run_id
         AND result.invocation_id = dependency.invocation_id
         AND result.logical_job_id = dependency.prerequisite_job_id
         AND result.claim_state = 'finalized'
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.state = 'preparing'
          AND prerequisite_job.logical_key = NEW.logical_key
          AND prerequisite_job.source_order = NEW.source_order
          AND result.descriptor_digest = NEW.result_descriptor_digest
          AND result.outputs_digest = NEW.outputs_digest
          AND result.commit_digest = NEW.commit_digest
          AND result.effective_conclusion = NEW.effective_conclusion
          AND result.closure_has_failure = NEW.closure_has_failure
          AND result.closure_has_cancelled = NEW.closure_has_cancelled
          AND result.closure_has_skipped = NEW.closure_has_skipped
          AND result.output_count = NEW.output_count
          AND result.finalized_at_ms = NEW.finalized_at_ms
          AND NEW.finalized_at_ms <= claim.evidence_ready_at_ms
    ) THEN
        RAISE EXCEPTION 'logical activation prerequisite pin lacks exact finalized result'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_logical_activation_preparation_output()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_preparation_prerequisites AS pin
        JOIN workflow_plan_v2_activation_preparation_claims AS claim
          ON claim.logical_job_id = pin.logical_job_id
         AND claim.state = 'preparing'
        JOIN workflow_plan_v2_effective_job_result_outputs AS output
          ON output.logical_job_id = pin.prerequisite_job_id
         AND output.output_name = NEW.output_name
        WHERE pin.logical_job_id = NEW.logical_job_id
          AND pin.prerequisite_job_id = NEW.prerequisite_job_id
          AND output.sensitivity = NEW.sensitivity
          AND output.public_value IS NOT DISTINCT FROM NEW.public_value
    ) THEN
        RAISE EXCEPTION 'logical activation output pin lacks exact classified result output'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_job_result_prerequisite()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_results AS logical_result
        JOIN workflow_plan_v2_job_result_claims AS logical_claim
          ON logical_claim.logical_job_id = logical_result.logical_job_id
        JOIN workflow_plan_v2_dependencies AS dependency
          ON dependency.logical_job_id = logical_result.logical_job_id
         AND dependency.run_id = logical_result.run_id
         AND dependency.invocation_id = logical_result.invocation_id
         AND dependency.prerequisite_job_id = NEW.prerequisite_job_id
        JOIN workflow_plan_v2_jobs AS prerequisite_job
          ON prerequisite_job.id = dependency.prerequisite_job_id
        JOIN workflow_plan_v2_effective_job_results AS prerequisite
          ON prerequisite.run_id = dependency.run_id
         AND prerequisite.invocation_id = dependency.invocation_id
         AND prerequisite.logical_job_id = dependency.prerequisite_job_id
         AND prerequisite.claim_state = 'finalized'
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND logical_claim.state = 'aggregating'
          AND prerequisite_job.source_order = NEW.prerequisite_source_order
          AND prerequisite.commit_digest = NEW.prerequisite_commit_digest
          AND prerequisite.outputs_digest = NEW.prerequisite_outputs_digest
          AND prerequisite.effective_conclusion = NEW.effective_conclusion
          AND prerequisite.closure_has_failure = NEW.closure_has_failure
          AND prerequisite.closure_has_cancelled = NEW.closure_has_cancelled
          AND prerequisite.closure_has_skipped = NEW.closure_has_skipped
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 prerequisite closure evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;
