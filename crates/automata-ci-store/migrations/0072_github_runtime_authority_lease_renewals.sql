-- Preserve immutable GitHub authority identity while allowing an exact runner
-- lease to advance through database-authorized renewals. The issuance's
-- original lease horizon remains part of its encrypted identity; each later
-- horizon is instead retained as append-only evidence in the same transaction
-- that mutates the attempt.

CREATE TABLE github_runtime_authority_lease_renewal_receipts (
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    lease_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    previous_lease_expires_at_ms BIGINT NOT NULL,
    renewed_lease_expires_at_ms BIGINT NOT NULL,
    authorized_at_ms BIGINT NOT NULL,
    CONSTRAINT github_runtime_authority_lease_renewal_receipts_pk PRIMARY KEY (
        attempt_id, fencing_token, renewed_lease_expires_at_ms
    ),
    CONSTRAINT github_runtime_authority_lease_renewal_predecessor_unique
        UNIQUE (attempt_id, fencing_token, previous_lease_expires_at_ms),
    CONSTRAINT github_runtime_authority_lease_renewal_receipts_authority_fk
        FOREIGN KEY (attempt_id, fencing_token)
        REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token)
        ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_lease_renewal_receipts_interval CHECK (
        fencing_token > 0
        AND runner_session_epoch > 0
        AND runner_generation > 0
        AND previous_lease_expires_at_ms > authorized_at_ms
        AND renewed_lease_expires_at_ms > previous_lease_expires_at_ms
        AND authorized_at_ms >= 0
        AND renewed_lease_expires_at_ms > authorized_at_ms
    ),
    CONSTRAINT github_runtime_authority_lease_renewal_receipts_non_nil CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND lease_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND runner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND runner_session_id <> '00000000-0000-0000-0000-000000000000'::UUID
    )
);

-- Quiesce both old heartbeat writers and authority reconciliation before
-- deciding whether every READY authority still has its immutable root
-- horizon. There is no safe receipt to fabricate for a preexisting mismatch.
LOCK TABLE job_attempts IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE github_runtime_authority_issuances IN SHARE ROW EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        JOIN job_attempts AS attempt
          ON attempt.id = authority.attempt_id
         AND attempt.fencing_token = authority.fencing_token
        WHERE authority.state = 'ready'
          AND attempt.lease_expires_at_ms <> authority.lease_expires_at_ms
    ) THEN
        RAISE EXCEPTION 'ready GitHub runtime authority has an unevidenced lease horizon'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_lease_renewal_legacy_current';
    END IF;
END;
$automata$;

CREATE FUNCTION automata_github_runtime_authority_lease_horizon_is_tail(
    authority github_runtime_authority_issuances,
    horizon BIGINT,
    observed_at BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT (
        horizon = authority.lease_expires_at_ms
        AND NOT EXISTS (
            SELECT 1
            FROM github_runtime_authority_lease_renewal_receipts AS any_renewal
            WHERE any_renewal.attempt_id = authority.attempt_id
              AND any_renewal.fencing_token = authority.fencing_token
        )
    ) OR EXISTS (
        SELECT 1
        FROM github_runtime_authority_lease_renewal_receipts AS tail
        WHERE tail.attempt_id = authority.attempt_id
          AND tail.fencing_token = authority.fencing_token
          AND tail.lease_id = authority.lease_id
          AND tail.runner_id = authority.runner_id
          AND tail.runner_session_id = authority.runner_session_id
          AND tail.runner_session_epoch = authority.runner_session_epoch
          AND tail.runner_generation = authority.runner_generation
          AND tail.renewed_lease_expires_at_ms = horizon
          AND tail.authorized_at_ms <= observed_at
          AND NOT EXISTS (
              SELECT 1
              FROM github_runtime_authority_lease_renewal_receipts AS successor
              WHERE successor.attempt_id = tail.attempt_id
                AND successor.fencing_token = tail.fencing_token
                AND successor.previous_lease_expires_at_ms =
                    tail.renewed_lease_expires_at_ms
          )
    )
$automata$;

CREATE FUNCTION automata_validate_github_runtime_authority_lease_renewal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM github_runtime_authority_issuances AS authority
    JOIN job_attempts AS attempt
      ON attempt.id = authority.attempt_id
     AND attempt.job_id = authority.job_id
    WHERE authority.attempt_id = NEW.attempt_id
      AND authority.fencing_token = NEW.fencing_token
      AND authority.lease_id = NEW.lease_id
      AND authority.runner_id = NEW.runner_id
      AND authority.runner_session_id = NEW.runner_session_id
      AND authority.runner_session_epoch = NEW.runner_session_epoch
      AND authority.runner_generation = NEW.runner_generation
      AND authority.state = 'ready'
      AND authority.ready_at_ms <= NEW.authorized_at_ms
      AND authority.provider_expires_at_ms IS NOT NULL
      AND authority.provider_expires_at_ms - 60000
            >= NEW.renewed_lease_expires_at_ms
      AND attempt.fencing_token = authority.fencing_token
      AND attempt.lease_id = authority.lease_id
      AND attempt.lease_issued_at_ms = authority.lease_issued_at_ms
      AND attempt.lease_expires_at_ms = NEW.previous_lease_expires_at_ms
      AND attempt.runner_id = authority.runner_id
      AND attempt.runner_session_id = authority.runner_session_id
      AND attempt.runner_session_epoch = authority.runner_session_epoch
      AND attempt.runner_generation = authority.runner_generation
      AND attempt.changed_at_ms <= NEW.authorized_at_ms
      AND automata_github_runtime_authority_lease_horizon_is_tail(
          authority,
          NEW.previous_lease_expires_at_ms,
          NEW.authorized_at_ms
      )
    FOR SHARE OF authority, attempt;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub runtime authority lease renewal lacks exact durable authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_lease_renewal_receipts_authority';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_lease_renewal_receipts_validate
BEFORE INSERT ON github_runtime_authority_lease_renewal_receipts
FOR EACH ROW
EXECUTE FUNCTION automata_validate_github_runtime_authority_lease_renewal();

CREATE FUNCTION automata_github_runtime_authority_lease_final_exact(
    checked_attempt_id UUID,
    checked_fencing_token BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        JOIN job_attempts AS attempt
          ON attempt.id = authority.attempt_id
         AND attempt.job_id = authority.job_id
        JOIN github_runtime_authority_lease_renewal_receipts AS tail
          ON tail.attempt_id = authority.attempt_id
         AND tail.fencing_token = authority.fencing_token
         AND tail.lease_id = authority.lease_id
         AND tail.runner_id = authority.runner_id
         AND tail.runner_session_id = authority.runner_session_id
         AND tail.runner_session_epoch = authority.runner_session_epoch
         AND tail.runner_generation = authority.runner_generation
         AND tail.renewed_lease_expires_at_ms = attempt.lease_expires_at_ms
         AND tail.authorized_at_ms = attempt.changed_at_ms
        WHERE authority.attempt_id = checked_attempt_id
          AND authority.fencing_token = checked_fencing_token
          AND authority.state = 'ready'
          AND attempt.fencing_token = authority.fencing_token
          AND attempt.lease_id = authority.lease_id
          AND attempt.runner_id = authority.runner_id
          AND attempt.runner_session_id = authority.runner_session_id
          AND attempt.runner_session_epoch = authority.runner_session_epoch
          AND attempt.runner_generation = authority.runner_generation
          AND NOT EXISTS (
              SELECT 1
              FROM github_runtime_authority_lease_renewal_receipts AS successor
              WHERE successor.attempt_id = tail.attempt_id
                AND successor.fencing_token = tail.fencing_token
                AND successor.previous_lease_expires_at_ms =
                    tail.renewed_lease_expires_at_ms
          )
    )
$automata$;

CREATE FUNCTION automata_require_github_runtime_authority_lease_final_exact()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT automata_github_runtime_authority_lease_final_exact(
        NEW.attempt_id,
        NEW.fencing_token
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority lease renewal is not reciprocal'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_lease_renewal_final_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER github_runtime_authority_lease_renewal_final_exact
AFTER INSERT ON github_runtime_authority_lease_renewal_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_github_runtime_authority_lease_final_exact();

CREATE FUNCTION automata_require_github_runtime_authority_attempt_renewal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = NEW.id
          AND authority.fencing_token = NEW.fencing_token
          AND authority.state = 'ready'
    ) AND NOT automata_github_runtime_authority_lease_final_exact(
        NEW.id,
        NEW.fencing_token
    ) THEN
        RAISE EXCEPTION 'ready GitHub runtime authority lease edit lacks evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_attempt_renewal_final_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER job_attempts_github_runtime_authority_renewal_exact
AFTER UPDATE ON job_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (OLD.lease_expires_at_ms IS DISTINCT FROM NEW.lease_expires_at_ms)
EXECUTE FUNCTION automata_require_github_runtime_authority_attempt_renewal();

CREATE FUNCTION automata_reject_github_runtime_authority_lease_renewal_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub runtime authority lease renewal evidence is append-only'
        USING ERRCODE = 'check_violation',
              CONSTRAINT =
                  'github_runtime_authority_lease_renewal_receipts_append_only';
END;
$automata$;

CREATE TRIGGER github_runtime_authority_lease_renewal_receipts_reject_mutation
BEFORE UPDATE OR DELETE ON github_runtime_authority_lease_renewal_receipts
FOR EACH ROW
EXECUTE FUNCTION automata_reject_github_runtime_authority_lease_renewal_mutation();

CREATE TRIGGER github_runtime_authority_lease_renewal_receipts_reject_truncate
BEFORE TRUNCATE ON github_runtime_authority_lease_renewal_receipts
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_github_runtime_authority_lease_renewal_mutation();

-- Rebind currentness to either the immutable issued horizon or one exact
-- append-only renewal horizon. All manifest, workflow, runner, fence, and
-- lifecycle proofs from 0065 remain unchanged.

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
          AND automata_github_runtime_authority_lease_horizon_is_tail(
              authority,
              attempt.lease_expires_at_ms,
              observed_at
          )
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
              authority.lease_expires_at_ms,
              authority.lease_issued_at_ms + 120000
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
