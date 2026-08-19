-- Canonical greenfield schema stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_github_runtime_authority_hash_bytes(value bytea) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
    SELECT pg_catalog.int8send(pg_catalog.octet_length(value)::BIGINT) || value
$$;

CREATE FUNCTION automata_github_runtime_authority_is_current(authority github_runtime_authority_issuances, observed_at bigint) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT automata_github_runtime_authority_base_is_current(authority, observed_at)
       AND automata_github_runtime_authority_has_provenance(authority)
$$;

CREATE FUNCTION automata_github_runtime_authority_lease_final_exact(checked_attempt_id uuid, checked_fencing_token bigint) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT EXISTS (
        SELECT 1
        FROM runners AS runner
        JOIN runner_sessions AS session
          ON session.runner_id = runner.id
        JOIN job_attempts AS attempt
          ON attempt.runner_id = runner.id
         AND attempt.runner_session_id = session.id
        JOIN github_runtime_authority_issuances AS authority
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
          AND attempt.lease_issued_at_ms = authority.lease_issued_at_ms
          AND attempt.runner_id = authority.runner_id
          AND attempt.runner_session_id = authority.runner_session_id
          AND attempt.runner_session_epoch = authority.runner_session_epoch
          AND attempt.runner_generation = authority.runner_generation
          AND attempt.lifecycle IN ('leased', 'preparing', 'running', 'cancelling')
          AND attempt.changed_at_ms < attempt.lease_expires_at_ms
          AND runner.id = authority.runner_id
          AND runner.tenant_id = authority.tenant_id
          AND runner.generation = authority.runner_generation
          AND runner.session_epoch = authority.runner_session_epoch
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND session.id = authority.runner_session_id
          AND session.session_epoch = authority.runner_session_epoch
          AND session.runner_generation = authority.runner_generation
          AND session.disconnected_at_ms IS NULL
          AND session.job_ir_schema = 1
          AND NOT EXISTS (
              SELECT 1
              FROM github_runtime_authority_lease_renewal_receipts AS successor
              WHERE successor.attempt_id = tail.attempt_id
                AND successor.fencing_token = tail.fencing_token
                AND successor.previous_lease_expires_at_ms =
                    tail.renewed_lease_expires_at_ms
          )
    )
$$;

CREATE FUNCTION automata_github_runtime_authority_lease_horizon_is_tail(authority github_runtime_authority_issuances, horizon bigint, observed_at bigint) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
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
$$;

CREATE FUNCTION automata_github_runtime_authority_operation_digest(request_kind text, attempt_id uuid, fencing_token bigint, claim_fence bigint, claim_owner_id uuid, claim_claimed_at_ms bigint, claim_expires_at_ms bigint, observed_at_ms bigint, retry_at_ms bigint, failure_kind text, commit_disposition text, provider_expires_at_ms bigint, safe_erase_after_ms bigint, plaintext_schema integer, plaintext_size_bytes bigint, plaintext_digest bytea, aad_digest bytea, envelope_digest bytea) RETURNS bytea
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT CASE
        WHEN request_kind = 'mint_commit' THEN pg_catalog.sha256(
            pg_catalog.convert_to(
                'automata.store.github-runtime-authority-operation.mint-commit.v4',
                'UTF8'
            ) || pg_catalog.decode('00', 'hex')
            || pg_catalog.uuid_send(attempt_id)
            || pg_catalog.int8send(fencing_token)
            || pg_catalog.uuid_send(claim_owner_id)
            || pg_catalog.int8send(claim_fence)
            || pg_catalog.int8send(claim_claimed_at_ms)
            || pg_catalog.int8send(claim_expires_at_ms)
            || automata_github_runtime_authority_hash_bytes(
                pg_catalog.convert_to(commit_disposition, 'UTF8')
            )
            || pg_catalog.int8send(observed_at_ms)
            || CASE WHEN provider_expires_at_ms IS NULL
                THEN pg_catalog.decode('00', 'hex')
                ELSE pg_catalog.decode('01', 'hex')
                    || pg_catalog.int8send(provider_expires_at_ms)
            END
            || pg_catalog.int8send(safe_erase_after_ms)
            || pg_catalog.int2send(plaintext_schema::SMALLINT)
            || pg_catalog.int8send(plaintext_size_bytes)
            || plaintext_digest || aad_digest || envelope_digest
        )
        WHEN request_kind = 'quarantine' THEN pg_catalog.sha256(
            pg_catalog.convert_to(
                'automata.store.github-runtime-authority-operation.quarantine.v4',
                'UTF8'
            ) || pg_catalog.decode('00', 'hex')
            || pg_catalog.uuid_send(attempt_id)
            || pg_catalog.int8send(fencing_token)
            || aad_digest
            || automata_github_runtime_authority_hash_bytes(
                pg_catalog.convert_to(failure_kind, 'UTF8')
            )
            || pg_catalog.int8send(observed_at_ms)
        )
        WHEN request_kind IN (
            'revocation_retry', 'revocation_defer', 'revocation_confirm'
        ) THEN pg_catalog.sha256(
            pg_catalog.convert_to(
                'automata.store.github-runtime-authority-operation.revocation-outcome.v4',
                'UTF8'
            ) || pg_catalog.decode('00', 'hex')
            || automata_github_runtime_authority_hash_bytes(
                pg_catalog.convert_to(
                    CASE request_kind
                        WHEN 'revocation_retry' THEN 'retry'
                        WHEN 'revocation_defer' THEN 'defer'
                        ELSE 'confirm'
                    END,
                    'UTF8'
                )
            )
            || pg_catalog.uuid_send(attempt_id)
            || pg_catalog.int8send(fencing_token)
            || pg_catalog.uuid_send(claim_owner_id)
            || pg_catalog.int8send(claim_fence)
            || pg_catalog.int8send(claim_claimed_at_ms)
            || pg_catalog.int8send(claim_expires_at_ms)
            || CASE WHEN request_kind = 'revocation_confirm' THEN ''::BYTEA
                    ELSE automata_github_runtime_authority_hash_bytes(
                        pg_catalog.convert_to(failure_kind, 'UTF8')
                    )
               END
            || pg_catalog.int8send(observed_at_ms)
            || CASE WHEN request_kind = 'revocation_retry'
                    THEN pg_catalog.int8send(retry_at_ms)
                    ELSE ''::BYTEA
               END
        )
    END
$$;

CREATE FUNCTION automata_github_runtime_authority_same_non_operation_state(prior github_runtime_authority_issuances, candidate github_runtime_authority_issuances) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT (
        to_jsonb(candidate) - ARRAY[
            'operation_request_kind', 'operation_request_claim_fence',
            'operation_request_claim_owner_id',
            'operation_request_observed_at_ms',
            'operation_request_retry_at_ms',
            'operation_request_failure_kind',
            'operation_request_commit_disposition',
            'operation_request_provider_expires_at_ms',
            'operation_request_safe_erase_after_ms',
            'operation_request_plaintext_schema',
            'operation_request_plaintext_size_bytes',
            'operation_request_plaintext_digest',
            'operation_request_aad_digest',
            'operation_request_envelope_digest'
        ]
    ) IS NOT DISTINCT FROM (
        to_jsonb(prior) - ARRAY[
            'operation_request_kind', 'operation_request_claim_fence',
            'operation_request_claim_owner_id',
            'operation_request_observed_at_ms',
            'operation_request_retry_at_ms',
            'operation_request_failure_kind',
            'operation_request_commit_disposition',
            'operation_request_provider_expires_at_ms',
            'operation_request_safe_erase_after_ms',
            'operation_request_plaintext_schema',
            'operation_request_plaintext_size_bytes',
            'operation_request_plaintext_digest',
            'operation_request_aad_digest',
            'operation_request_envelope_digest'
        ]
    )
$$;

CREATE FUNCTION automata_github_runtime_authority_same_operation_request(prior github_runtime_authority_issuances, candidate github_runtime_authority_issuances) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT ROW(
        candidate.operation_request_kind,
        candidate.operation_request_claim_fence,
        candidate.operation_request_claim_owner_id,
        candidate.operation_request_observed_at_ms,
        candidate.operation_request_retry_at_ms,
        candidate.operation_request_failure_kind,
        candidate.operation_request_commit_disposition,
        candidate.operation_request_provider_expires_at_ms,
        candidate.operation_request_safe_erase_after_ms,
        candidate.operation_request_plaintext_schema,
        candidate.operation_request_plaintext_size_bytes,
        candidate.operation_request_plaintext_digest,
        candidate.operation_request_aad_digest,
        candidate.operation_request_envelope_digest
    ) IS NOT DISTINCT FROM ROW(
        prior.operation_request_kind,
        prior.operation_request_claim_fence,
        prior.operation_request_claim_owner_id,
        prior.operation_request_observed_at_ms,
        prior.operation_request_retry_at_ms,
        prior.operation_request_failure_kind,
        prior.operation_request_commit_disposition,
        prior.operation_request_provider_expires_at_ms,
        prior.operation_request_safe_erase_after_ms,
        prior.operation_request_plaintext_schema,
        prior.operation_request_plaintext_size_bytes,
        prior.operation_request_plaintext_digest,
        prior.operation_request_aad_digest,
        prior.operation_request_envelope_digest
    )
$$;

CREATE FUNCTION automata_github_runtime_authority_base_is_current(authority github_runtime_authority_issuances, observed_at bigint) RETURNS boolean
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
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.run_id = run.id
         AND concrete.job_id = job.id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = run.id
         AND invocation.id = concrete.invocation_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = run.id
         AND logical_job.invocation_id = invocation.id
         AND logical_job.id = concrete.logical_job_id
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
          ON instance.run_id = activation_publication.run_id
         AND instance.invocation_id = activation_publication.invocation_id
         AND instance.logical_job_id = activation_publication.logical_job_id
         AND instance.id = concrete.instance_id
        JOIN logical_workflow_materialization_claims AS materialization
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
          AND job.admission_epoch = 1
          AND job.job_ir_schema = 1
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
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
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
          AND automata_logical_workflow_invocation_published(
              run.id, invocation.id
          )
          AND invocation.plan_schema = 1
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
          AND activation_publication.job_ir_version = 1
          AND activation_publication.runtime_context_schema = 1
          AND instance.job_ir_version = 1
          AND instance.job_ir_digest = job.job_ir_digest
          AND instance.job_ir_size_bytes = job.job_ir_size_bytes
          AND instance.job_ir_object_key = job.job_ir_object_key
          AND instance.job_ir_media_type =
              'application/vnd.automata.job-ir.protobuf'
          AND materialization.state = 'materialized'
          AND concrete.runtime_context_schema = 1
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
          AND contents_authority.state = 'active'
          AND contents_authority.created_at_ms <= observed_at
          AND contents_authority.state_updated_at_ms <= observed_at
          AND origin.admitted_at_ms <= observed_at
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND session.job_ir_schema = 1
          AND session.disconnected_at_ms IS NULL
    )
$$;

CREATE FUNCTION automata_github_schedule_check_evidence_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    exact BOOLEAN;
    now_ms BIGINT;
BEGIN
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT TRUE INTO exact
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
    JOIN github_server_service_authorities AS authority
      ON authority.tenant_id = registry.tenant_id
     AND authority.id = NEW.checks_authority_id
    JOIN github_check_subjects AS subject
      ON subject.tenant_id = fire.tenant_id
     AND subject.repository_id = fire.repository_id
     AND subject.provider_connection_id = fire.provider_connection_id
     AND subject.schedule_fire_id = fire.fire_id
     AND subject.id = NEW.github_check_subject_id
    WHERE fire.fire_id = NEW.schedule_fire_id
      AND fire.tenant_id = NEW.tenant_id
      AND fire.repository_id = NEW.repository_id
      AND fire.provider_connection_id = NEW.provider_connection_id
      AND fire.registry_id = NEW.registry_id
      AND fire.entry_ordinal = NEW.entry_ordinal
      AND fire.scheduled_at_ms = NEW.scheduled_at_ms
      AND fire.state = 'claimed'
      AND fire.claimed_at_ms <= now_ms
      AND fire.claim_expires_at_ms > now_ms
      AND NEW.recorded_at_ms >= fire.claimed_at_ms
      AND NEW.recorded_at_ms < fire.claim_expires_at_ms
      AND registry.manifest_revision = NEW.provider_manifest_revision
      AND registry.manifest_digest = NEW.provider_manifest_digest
      AND registry.default_branch_ref = NEW.default_branch_ref
      AND registry.source_revision = NEW.source_revision
      AND registry.github_repository_owner_id = NEW.github_repository_owner_id
      AND registry.default_branch_ref = manifest.git_ref
      AND NEW.github_check_head_sha = decode(registry.source_revision, 'hex')
      AND subject.origin_kind = 'scheduled_fire'
      AND subject.provider_delivery_id IS NULL
      AND subject.subject_key = entry.workflow_path
      AND subject.provider_installation_id = manifest.provider_installation_id
      AND subject.github_repository_id = manifest.github_repository_id
      AND subject.github_repository_name = manifest.github_repository_name
      AND subject.github_app_id = manifest.github_app_id
      AND subject.head_sha = NEW.github_check_head_sha
      AND subject.check_name = manifest.check_name
      AND subject.created_at_ms = NEW.recorded_at_ms
      AND authority.repository_id = registry.repository_id
      AND authority.provider_connection_id = registry.provider_connection_id
      AND authority.provider_installation_id = manifest.provider_installation_id
      AND authority.github_app_id = manifest.github_app_id
      AND authority.github_repository_id = manifest.github_repository_id
      AND authority.github_repository_name = manifest.github_repository_name
      AND authority.service_scope = 'checks_write'
      AND authority.github_app_client_id = manifest.github_app_client_id
      AND authority.github_app_jwt_issuer_kind = manifest.github_app_jwt_issuer_kind
      AND authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
      AND authority.app_configuration_revision =
          NEW.checks_authority_app_configuration_revision
      AND authority.app_configuration_revision = manifest.app_configuration_revision
      AND authority.policy_revision = NEW.checks_authority_policy_revision
      AND authority.policy_revision = manifest.policy_revision
      AND authority.identity_digest = NEW.checks_authority_identity_digest
      AND authority.state = 'active'
      AND authority.created_at_ms <= NEW.recorded_at_ms
    FOR SHARE OF fire, registry, entry, seal, current, manifest, manifest_current,
                 authority, subject;
    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'GitHub schedule Check evidence is not exact and live'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_check_evidence_authority_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_schedule_check_requires_atomic_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    evidence github_schedule_check_evidence%ROWTYPE;
    outbox github_check_projection_outbox%ROWTYPE;
BEGIN
    IF NEW.origin_kind <> 'scheduled_fire' OR NEW.subject_kind = 'job' THEN
        RETURN NULL;
    END IF;
    SELECT * INTO evidence
    FROM github_schedule_check_evidence
    WHERE schedule_fire_id = NEW.schedule_fire_id
      AND tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND provider_connection_id = NEW.provider_connection_id
      AND github_check_subject_id = NEW.id;
    SELECT * INTO outbox
    FROM github_check_projection_outbox
    WHERE subject_id = NEW.id;
    IF evidence.schedule_fire_id IS NULL
        OR evidence.github_check_head_sha <> NEW.head_sha
        OR evidence.recorded_at_ms <> NEW.created_at_ms
        OR outbox.subject_id IS NULL
        OR outbox.state <> 'pending'
        OR outbox.attempted_revision IS NOT NULL
        OR outbox.attempt_count <> 0
        OR outbox.claim_fence <> 0
        OR outbox.projected_revision <> 0
        OR outbox.state_updated_at_ms <> NEW.created_at_ms
    THEN
        RAISE EXCEPTION 'GitHub scheduled Check requires atomic sealed evidence and outbox'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_check_atomic_evidence_required';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_github_schedule_run_evidence_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    exact BOOLEAN;
    now_ms BIGINT;
BEGIN
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT TRUE INTO exact
    FROM github_schedule_fires AS fire
    JOIN github_schedule_registry_revisions AS registry
      ON registry.tenant_id = fire.tenant_id
     AND registry.repository_id = fire.repository_id
     AND registry.provider_connection_id = fire.provider_connection_id
     AND registry.registry_id = fire.registry_id
    JOIN github_schedule_registry_entries AS entry
     ON entry.registry_id = fire.registry_id
     AND entry.ordinal = fire.entry_ordinal
    JOIN github_provider_manifest_current AS manifest_current
      ON manifest_current.tenant_id = registry.tenant_id
     AND manifest_current.repository_id = registry.repository_id
     AND manifest_current.provider_connection_id = registry.provider_connection_id
     AND manifest_current.manifest_revision = registry.manifest_revision
     AND manifest_current.manifest_digest = registry.manifest_digest
    JOIN github_schedule_check_evidence AS schedule_check
      ON schedule_check.schedule_fire_id = fire.fire_id
     AND schedule_check.tenant_id = fire.tenant_id
     AND schedule_check.repository_id = fire.repository_id
     AND schedule_check.provider_connection_id = fire.provider_connection_id
     AND schedule_check.registry_id = fire.registry_id
     AND schedule_check.entry_ordinal = fire.entry_ordinal
    JOIN github_check_subjects AS check_subject
      ON check_subject.id = schedule_check.github_check_subject_id
     AND check_subject.tenant_id = schedule_check.tenant_id
    JOIN workflow_runs AS run
      ON run.repository_id = fire.repository_id
     AND run.id = NEW.run_id
    JOIN workflow_definitions AS workflow
      ON workflow.repository_id = run.repository_id
     AND workflow.id = run.workflow_id
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
    JOIN logical_workflow_runs AS marker
      ON marker.run_id = run.id
    JOIN workflow_admission_receipts AS admission
      ON admission.tenant_id = fire.tenant_id
     AND admission.idempotency_kind = 'operation'
     AND admission.idempotency_key = fire.fire_id::TEXT
     AND admission.repository_id = fire.repository_id
     AND admission.run_id = run.id
    WHERE fire.fire_id = NEW.schedule_fire_id
      AND fire.tenant_id = NEW.tenant_id
      AND fire.repository_id = NEW.repository_id
      AND fire.state = 'claimed'
      AND fire.claim_owner_id = NEW.admission_claim_owner_id
      AND fire.attempt_count = NEW.admission_claim_attempt
      AND fire.claim_fence = NEW.admission_claim_fence
      AND fire.claimed_at_ms = NEW.admission_claimed_at_ms
      AND fire.claim_expires_at_ms = NEW.admission_claim_expires_at_ms
      AND fire.claimed_at_ms <= now_ms
      AND fire.claim_expires_at_ms > now_ms
      AND registry.default_branch_ref = schedule_check.default_branch_ref
      AND registry.source_revision = schedule_check.source_revision
      AND registry.github_repository_owner_id = NEW.github_repository_owner_id
      AND schedule_check.github_repository_owner_id = NEW.github_repository_owner_id
      AND entry.workflow_path = NEW.workflow_path
      AND entry.workflow_source_digest = NEW.source_digest
      AND check_subject.origin_kind = 'scheduled_fire'
      AND check_subject.schedule_fire_id = fire.fire_id
      AND check_subject.provider_delivery_id IS NULL
      AND check_subject.workflow_run_id = run.id
      AND check_subject.linked_at_ms = NEW.admitted_at_ms
      AND check_subject.desired_state = 'in_progress'
      AND check_subject.head_sha = NEW.github_check_head_sha
      AND schedule_check.github_check_subject_id = NEW.github_check_subject_id
      AND schedule_check.github_check_head_sha = NEW.github_check_head_sha
      AND run.workflow_id = NEW.workflow_id
      AND run.snapshot_id = NEW.snapshot_id
      AND run.head_sha = NEW.github_check_head_sha
      AND run.git_ref = registry.default_branch_ref
      AND run.git_ref = NEW.git_ref
      AND run.event_name = 'schedule'
      AND run.event_name = NEW.event_name
      AND run.event_digest = NEW.event_digest
      AND run.plan_schema = NEW.workflow_plan_schema
      AND run.plan_digest = NEW.plan_digest
      AND run.created_at_ms = NEW.admitted_at_ms
      AND workflow.path = NEW.workflow_path
      AND snapshot.source_digest = NEW.source_digest
      AND marker.root_invocation_id = NEW.root_invocation_id
      AND marker.admission_digest = NEW.logical_admission_digest
      AND marker.admitted_at_ms = NEW.admitted_at_ms
      AND admission.request_digest = NEW.logical_admission_digest
      AND admission.committed_at_ms = NEW.admitted_at_ms
      AND admission.github_subject_evidence_required
    FOR SHARE OF fire, registry, entry, manifest_current, schedule_check, check_subject,
                 run, workflow, snapshot, marker, admission;
    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'GitHub scheduled run evidence is not exact and live'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_run_evidence_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_schedule_run_subject_evidence_digest(schedule_fire_id uuid, tenant_id text, repository_id uuid, workflow_id uuid, snapshot_id uuid, run_id uuid, root_invocation_id uuid, github_repository_owner_id bigint, admission_claim_owner_id uuid, admission_claim_attempt smallint, admission_claim_fence bigint, admission_claimed_at_ms bigint, admission_claim_expires_at_ms bigint, github_check_subject_id uuid, github_check_head_sha bytea, workflow_path text, source_digest bytea, event_name text, event_digest bytea, git_ref text, workflow_plan_schema smallint, plan_digest bytea, logical_admission_digest bytea, admitted_at_ms bigint) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.github-schedule-run-subject-evidence.v1', 'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || automata_digest_part(pg_catalog.uuid_send(schedule_fire_id))
    || automata_digest_part(pg_catalog.convert_to(tenant_id, 'UTF8'))
    || automata_digest_part(pg_catalog.uuid_send(repository_id))
    || automata_digest_part(pg_catalog.uuid_send(workflow_id))
    || automata_digest_part(pg_catalog.uuid_send(snapshot_id))
    || automata_digest_part(pg_catalog.uuid_send(run_id))
    || automata_digest_part(pg_catalog.uuid_send(root_invocation_id))
    || automata_digest_part(
        pg_catalog.int8send(github_repository_owner_id)
    )
    || automata_digest_part(
        pg_catalog.uuid_send(admission_claim_owner_id)
    )
    || automata_digest_part(
        pg_catalog.int8send(admission_claim_attempt::BIGINT)
    )
    || automata_digest_part(pg_catalog.int8send(admission_claim_fence))
    || automata_digest_part(pg_catalog.int8send(admission_claimed_at_ms))
    || automata_digest_part(
        pg_catalog.int8send(admission_claim_expires_at_ms)
    )
    || automata_digest_part(
        pg_catalog.uuid_send(github_check_subject_id)
    )
    || automata_digest_part(github_check_head_sha)
    || automata_digest_part(
        pg_catalog.convert_to(workflow_path, 'UTF8')
    )
    || automata_digest_part(source_digest)
    || automata_digest_part(
        pg_catalog.convert_to(event_name, 'UTF8')
    )
    || automata_digest_part(event_digest)
    || automata_digest_part(pg_catalog.convert_to(git_ref, 'UTF8'))
    || automata_digest_part(
        pg_catalog.int8send(workflow_plan_schema::BIGINT)
    )
    || automata_digest_part(plan_digest)
    || automata_digest_part(logical_admission_digest)
    || automata_digest_part(pg_catalog.int8send(admitted_at_ms))
)
$$;

CREATE FUNCTION automata_github_server_service_aad_digest(bytea, bigint, bigint, bigint, bigint, bigint, smallint, bigint, bytea) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $_$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.github-server-service.aad.v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || automata_digest_part($1)
    || automata_digest_part(pg_catalog.int8send($2))
    || automata_digest_part(pg_catalog.int8send($3))
    || automata_digest_part(pg_catalog.int8send($4))
    || automata_digest_part(
        CASE WHEN $5 IS NULL
            THEN pg_catalog.decode('00', 'hex')
            ELSE pg_catalog.decode('01', 'hex')
        END
    )
    || CASE WHEN $5 IS NULL THEN ''::BYTEA
        ELSE automata_digest_part(pg_catalog.int8send($5))
    END
    || automata_digest_part(pg_catalog.int8send($6))
    || automata_digest_part(pg_catalog.int2send($7))
    || automata_digest_part(pg_catalog.int8send($8))
    || automata_digest_part($9)
)
$_$;

CREATE FUNCTION automata_github_server_service_authority_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    repository repositories%ROWTYPE;
BEGIN
    SELECT * INTO repository
    FROM repositories
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.repository_id
    FOR SHARE;
    IF repository.id IS NULL
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner || '/' || repository.name <> NEW.github_repository_name
        OR NEW.state <> 'active'
        OR NEW.current_issuance_generation IS NOT NULL
        OR NEW.refresh_issuance_generation IS NOT NULL
        OR NEW.next_issuance_generation <> 1
        OR NEW.consecutive_generation_failures <> 0
        OR NEW.next_mint_not_before_ms IS NOT NULL
        OR NEW.mint_gate_generation IS NOT NULL
        OR NEW.failure_budget_rearm_at_ms IS NOT NULL
        OR NEW.state_updated_at_ms <> NEW.created_at_ms
        OR NEW.retired_at_ms IS NOT NULL
    THEN
        RAISE EXCEPTION 'GitHub server-service authority descriptor is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_initial_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_server_service_authority_update_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_state TEXT;
    refresh_state TEXT;
    refresh_updated_at_ms BIGINT;
    transition_state TEXT;
    transition_safe_erase_after_ms BIGINT;
    transition_updated_at_ms BIGINT;
    previous_current_state TEXT;
    previous_current_updated_at_ms BIGINT;
    gate_state TEXT;
    gate_terminal_reason TEXT;
    gate_generation_failure_gate_at_ms BIGINT;
    expected_gate_generation BIGINT;
    expected_gate_at_ms BIGINT;
    failure_gate_advanced BOOLEAN := FALSE;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.provider_installation_id IS DISTINCT FROM OLD.provider_installation_id
        OR NEW.github_app_id IS DISTINCT FROM OLD.github_app_id
        OR NEW.github_app_client_id IS DISTINCT FROM OLD.github_app_client_id
        OR NEW.github_app_jwt_issuer_kind IS DISTINCT FROM OLD.github_app_jwt_issuer_kind
        OR NEW.github_repository_id IS DISTINCT FROM OLD.github_repository_id
        OR NEW.github_repository_name IS DISTINCT FROM OLD.github_repository_name
        OR NEW.service_scope IS DISTINCT FROM OLD.service_scope
        OR NEW.permission_policy IS DISTINCT FROM OLD.permission_policy
        OR NEW.policy_digest IS DISTINCT FROM OLD.policy_digest
        OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
        OR NEW.app_key_spki_sha256 IS DISTINCT FROM OLD.app_key_spki_sha256
        OR NEW.app_configuration_revision IS DISTINCT FROM OLD.app_configuration_revision
        OR NEW.configuration_fingerprint IS DISTINCT FROM OLD.configuration_fingerprint
        OR NEW.identity_digest IS DISTINCT FROM OLD.identity_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.state_updated_at_ms < OLD.state_updated_at_ms
        OR NEW.next_issuance_generation < OLD.next_issuance_generation
    THEN
        RAISE EXCEPTION 'GitHub server-service authority identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_identity_immutable';
    END IF;
    IF NEW.state = 'active' AND OLD.state = 'active' THEN
        IF OLD.refresh_issuance_generation IS NOT NULL
            AND NEW.refresh_issuance_generation IS NULL
        THEN
            SELECT state, safe_erase_after_ms, state_updated_at_ms
            INTO transition_state, transition_safe_erase_after_ms,
                 transition_updated_at_ms
            FROM github_server_service_authority_issuances
            WHERE authority_id = NEW.id
              AND generation = OLD.refresh_issuance_generation;
            IF NEW.state_updated_at_ms IS DISTINCT FROM transition_updated_at_ms THEN
                RAISE EXCEPTION 'GitHub server-service refresh pointer time is not exact'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_authorities_pointer_time_exact';
            END IF;
            IF NEW.current_issuance_generation
                IS NOT DISTINCT FROM OLD.refresh_issuance_generation
            THEN
                IF OLD.current_issuance_generation IS NOT NULL THEN
                    SELECT state, state_updated_at_ms
                    INTO previous_current_state, previous_current_updated_at_ms
                    FROM github_server_service_authority_issuances
                    WHERE authority_id = NEW.id
                      AND generation = OLD.current_issuance_generation;
                END IF;
                IF transition_state IS DISTINCT FROM 'ready'
                    OR NEW.consecutive_generation_failures <> 0
                    OR NEW.next_mint_not_before_ms IS NOT NULL
                    OR NEW.mint_gate_generation IS NOT NULL
                    OR NEW.failure_budget_rearm_at_ms IS NOT NULL
                    OR OLD.current_issuance_generation IS NOT NULL
                        AND (
                            previous_current_state IS DISTINCT FROM 'revoke_pending'
                            OR previous_current_updated_at_ms
                                IS DISTINCT FROM transition_updated_at_ms
                        )
                THEN
                    RAISE EXCEPTION 'GitHub server-service ready generation did not reset its failure budget'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
            ELSIF NEW.current_issuance_generation
                IS NOT DISTINCT FROM OLD.current_issuance_generation
            THEN
                IF transition_state IS NULL
                    OR NEW.consecutive_generation_failures <> LEAST(
                        OLD.consecutive_generation_failures + 1, 32
                    )
                    OR NEW.failure_budget_rearm_at_ms::NUMERIC
                        IS DISTINCT FROM (CASE
                            WHEN OLD.consecutive_generation_failures = 31
                                THEN transition_updated_at_ms::NUMERIC + 86400000
                            ELSE OLD.failure_budget_rearm_at_ms::NUMERIC
                        END)
                    OR (
                        transition_state = 'rejected'
                        AND NEW.next_mint_not_before_ms
                            IS DISTINCT FROM GREATEST(
                                COALESCE(
                                    OLD.next_mint_not_before_ms,
                                    transition_updated_at_ms + 60000
                                ),
                                transition_updated_at_ms + 60000
                            )
                    )
                    OR (
                        transition_state = 'rejected'
                        AND NEW.mint_gate_generation IS DISTINCT FROM (CASE
                            WHEN OLD.next_mint_not_before_ms IS NULL
                                OR transition_updated_at_ms + 60000
                                    > OLD.next_mint_not_before_ms
                                THEN OLD.refresh_issuance_generation
                            ELSE OLD.mint_gate_generation
                        END)
                    )
                    OR (
                        transition_state IN ('indeterminate', 'revoke_pending')
                        AND NEW.next_mint_not_before_ms
                            IS DISTINCT FROM GREATEST(
                                COALESCE(
                                    OLD.next_mint_not_before_ms,
                                    transition_safe_erase_after_ms
                                ),
                                transition_safe_erase_after_ms
                            )
                    )
                    OR (
                        transition_state IN ('indeterminate', 'revoke_pending')
                        AND NEW.mint_gate_generation IS DISTINCT FROM (CASE
                            WHEN OLD.next_mint_not_before_ms IS NULL
                                OR transition_safe_erase_after_ms
                                    > OLD.next_mint_not_before_ms
                                THEN OLD.refresh_issuance_generation
                            ELSE OLD.mint_gate_generation
                        END)
                    )
                    OR transition_state NOT IN (
                        'rejected', 'indeterminate', 'revoke_pending'
                    )
                THEN
                    RAISE EXCEPTION 'GitHub server-service failed generation did not advance its failure budget'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
            ELSE
                RAISE EXCEPTION 'GitHub server-service refresh result changed an unrelated current generation'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
            END IF;
        ELSIF OLD.current_issuance_generation IS NOT NULL
            AND NEW.current_issuance_generation IS NULL
            AND NEW.refresh_issuance_generation
                IS NOT DISTINCT FROM OLD.refresh_issuance_generation
        THEN
            SELECT state, safe_erase_after_ms, state_updated_at_ms
            INTO transition_state, transition_safe_erase_after_ms,
                 transition_updated_at_ms
            FROM github_server_service_authority_issuances
            WHERE authority_id = NEW.id
              AND generation = OLD.current_issuance_generation;
            IF transition_state IS NULL
                OR NEW.state_updated_at_ms IS DISTINCT FROM transition_updated_at_ms
            THEN
                RAISE EXCEPTION 'GitHub server-service current reduction lacks its issuance'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
            ELSIF transition_state = 'quarantined' THEN
                IF NEW.consecutive_generation_failures <> LEAST(
                        OLD.consecutive_generation_failures + 1, 32
                    )
                    OR NEW.failure_budget_rearm_at_ms::NUMERIC
                        IS DISTINCT FROM (CASE
                            WHEN OLD.consecutive_generation_failures = 31
                                THEN transition_updated_at_ms::NUMERIC + 86400000
                            ELSE OLD.failure_budget_rearm_at_ms::NUMERIC
                        END)
                    OR NEW.next_mint_not_before_ms
                        IS DISTINCT FROM GREATEST(
                            COALESCE(
                                OLD.next_mint_not_before_ms,
                                transition_safe_erase_after_ms
                            ),
                            transition_safe_erase_after_ms
                        )
                    OR NEW.mint_gate_generation IS DISTINCT FROM (CASE
                        WHEN OLD.next_mint_not_before_ms IS NULL
                            OR transition_safe_erase_after_ms
                                > OLD.next_mint_not_before_ms
                            THEN OLD.current_issuance_generation
                        ELSE OLD.mint_gate_generation
                    END)
                THEN
                    RAISE EXCEPTION 'GitHub server-service quarantined current did not advance its failure budget'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
            ELSIF NEW.consecutive_generation_failures
                    IS DISTINCT FROM OLD.consecutive_generation_failures
                OR NEW.next_mint_not_before_ms
                    IS DISTINCT FROM OLD.next_mint_not_before_ms
                OR NEW.mint_gate_generation
                    IS DISTINCT FROM OLD.mint_gate_generation
                OR NEW.failure_budget_rearm_at_ms
                    IS DISTINCT FROM OLD.failure_budget_rearm_at_ms
            THEN
                RAISE EXCEPTION 'GitHub server-service current reduction rewrote its failure budget'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
            END IF;
        ELSIF NEW.consecutive_generation_failures
                IS DISTINCT FROM OLD.consecutive_generation_failures
            OR NEW.next_mint_not_before_ms
                IS DISTINCT FROM OLD.next_mint_not_before_ms
            OR NEW.mint_gate_generation
                IS DISTINCT FROM OLD.mint_gate_generation
            OR NEW.failure_budget_rearm_at_ms
                IS DISTINCT FROM OLD.failure_budget_rearm_at_ms
        THEN
            IF OLD.consecutive_generation_failures = 32
                AND OLD.refresh_issuance_generation IS NULL
                AND NEW.consecutive_generation_failures = 31
                AND NEW.next_mint_not_before_ms
                    IS NOT DISTINCT FROM OLD.next_mint_not_before_ms
                AND NEW.mint_gate_generation
                    IS NOT DISTINCT FROM OLD.mint_gate_generation
                AND NEW.failure_budget_rearm_at_ms IS NULL
                AND OLD.next_mint_not_before_ms <= NEW.state_updated_at_ms
                AND OLD.failure_budget_rearm_at_ms <= NEW.state_updated_at_ms
                AND NEW.current_issuance_generation
                    IS NOT DISTINCT FROM OLD.current_issuance_generation
                AND NEW.refresh_issuance_generation
                    IS NOT DISTINCT FROM OLD.refresh_issuance_generation
                AND NEW.next_issuance_generation
                    IS NOT DISTINCT FROM OLD.next_issuance_generation
            THEN
                failure_gate_advanced := TRUE;
            ELSE
                SELECT state, terminal_reason, state_updated_at_ms,
                       generation_failure_gate_at_ms
                INTO gate_state, gate_terminal_reason, transition_updated_at_ms,
                     gate_generation_failure_gate_at_ms
                FROM github_server_service_authority_issuances
                WHERE authority_id = NEW.id
                  AND generation = OLD.mint_gate_generation;
                IF gate_state = 'revoked'
                    AND gate_terminal_reason = 'provider_revoked'
                THEN
                    NULL;
                ELSIF gate_state = 'revoke_pending'
                    AND gate_generation_failure_gate_at_ms IS NOT NULL
                    AND gate_generation_failure_gate_at_ms
                        < OLD.next_mint_not_before_ms
                THEN
                    NULL;
                ELSE
                    RAISE EXCEPTION 'GitHub server-service failure gate lacks exact reduction evidence'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
                SELECT generation, effective_gate_at_ms
                INTO expected_gate_generation, expected_gate_at_ms
                FROM (
                    SELECT generation,
                           CASE
                               WHEN state = 'revoked'
                                    AND terminal_reason = 'provider_revoked'
                                   THEN LEAST(
                                       generation_failure_gate_at_ms::NUMERIC,
                                       state_updated_at_ms::NUMERIC + 60000
                                   )::BIGINT
                               ELSE generation_failure_gate_at_ms
                           END AS effective_gate_at_ms
                    FROM github_server_service_authority_issuances
                    WHERE authority_id = NEW.id
                      AND generation_failure_gate_at_ms IS NOT NULL
                ) AS failure_gate
                ORDER BY effective_gate_at_ms DESC, generation DESC
                LIMIT 1;
                IF expected_gate_generation IS NULL
                    OR OLD.mint_gate_generation IS NULL
                    OR NEW.current_issuance_generation
                        IS DISTINCT FROM OLD.current_issuance_generation
                    OR NEW.refresh_issuance_generation
                        IS DISTINCT FROM OLD.refresh_issuance_generation
                    OR NEW.next_issuance_generation
                        IS DISTINCT FROM OLD.next_issuance_generation
                    OR NEW.consecutive_generation_failures
                        IS DISTINCT FROM OLD.consecutive_generation_failures
                    OR NEW.next_mint_not_before_ms
                        IS DISTINCT FROM expected_gate_at_ms
                    OR NEW.mint_gate_generation
                        IS DISTINCT FROM expected_gate_generation
                    OR NEW.failure_budget_rearm_at_ms
                        IS DISTINCT FROM OLD.failure_budget_rearm_at_ms
                    OR NEW.state_updated_at_ms
                        IS DISTINCT FROM transition_updated_at_ms
                THEN
                    RAISE EXCEPTION 'GitHub server-service lifecycle rewrote its failure budget'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
                failure_gate_advanced := TRUE;
            END IF;
        END IF;
    ELSIF NEW.consecutive_generation_failures
            IS DISTINCT FROM OLD.consecutive_generation_failures
        OR NEW.next_mint_not_before_ms
            IS DISTINCT FROM OLD.next_mint_not_before_ms
        OR NEW.mint_gate_generation
            IS DISTINCT FROM OLD.mint_gate_generation
        OR NEW.failure_budget_rearm_at_ms
            IS DISTINCT FROM OLD.failure_budget_rearm_at_ms
    THEN
        RAISE EXCEPTION 'GitHub server-service non-active lifecycle rewrote its failure budget'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
    END IF;
    IF NEW.next_issuance_generation IS DISTINCT FROM OLD.next_issuance_generation THEN
        IF OLD.state <> 'active'
            OR OLD.refresh_issuance_generation IS NOT NULL
            OR NEW.next_issuance_generation <> OLD.next_issuance_generation + 1
            OR NEW.refresh_issuance_generation
                IS DISTINCT FROM OLD.next_issuance_generation
        THEN
            RAISE EXCEPTION 'GitHub server-service next generation was not reserved exactly'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_authorities_next_generation_exact';
        END IF;
    ELSIF OLD.refresh_issuance_generation IS NULL
        AND NEW.refresh_issuance_generation IS NOT NULL
    THEN
        RAISE EXCEPTION 'GitHub server-service refresh lacks generation reservation'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_next_generation_exact';
    END IF;
    IF NOT (
        NEW.state = OLD.state
        OR OLD.state = 'active' AND NEW.state = 'retiring'
        OR OLD.state = 'retiring' AND NEW.state = 'retired'
    ) THEN
        RAISE EXCEPTION 'GitHub server-service authority state transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_state_transition';
    END IF;
    IF NEW.state = OLD.state AND NOT failure_gate_advanced AND (
        OLD.state <> 'active'
        OR (
            NEW.current_issuance_generation
                IS NOT DISTINCT FROM OLD.current_issuance_generation
            AND NEW.refresh_issuance_generation
                IS NOT DISTINCT FROM OLD.refresh_issuance_generation
        )
    ) THEN
        RAISE EXCEPTION 'GitHub server-service authority replay rewrote lifecycle evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_same_state_exact';
    END IF;
    IF OLD.state = 'retiring' AND NEW.state = 'retired' AND EXISTS (
        SELECT 1
        FROM github_server_service_authority_issuances
        WHERE authority_id = NEW.id
          AND (
              state NOT IN ('rejected', 'revoked')
              OR envelope_schema IS NOT NULL
          )
    ) THEN
        RAISE EXCEPTION 'GitHub server-service authority retired with retained custody'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_retired_terminal_exact';
    END IF;
    IF NEW.current_issuance_generation IS NOT NULL THEN
        SELECT state INTO current_state
        FROM github_server_service_authority_issuances
        WHERE authority_id = NEW.id
          AND generation = NEW.current_issuance_generation;
        IF current_state IS DISTINCT FROM 'ready' THEN
            RAISE EXCEPTION 'GitHub server-service current generation is not ready'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_authorities_current_ready';
        END IF;
    END IF;
    IF NEW.refresh_issuance_generation IS NOT NULL THEN
        SELECT state, state_updated_at_ms
        INTO refresh_state, refresh_updated_at_ms
        FROM github_server_service_authority_issuances
        WHERE authority_id = NEW.id
          AND generation = NEW.refresh_issuance_generation;
        IF refresh_state NOT IN ('claimed', 'minting', 'mint_retry')
            OR (
                NEW.refresh_issuance_generation
                    IS DISTINCT FROM OLD.refresh_issuance_generation
                AND NEW.state_updated_at_ms IS DISTINCT FROM refresh_updated_at_ms
            )
        THEN
            RAISE EXCEPTION 'GitHub server-service refresh generation is not mintable'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_authorities_refresh_mintable';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_server_service_handoff_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    issuance github_server_service_authority_issuances%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    check_outbox github_check_projection_outbox%ROWTYPE;
    check_subject github_check_subjects%ROWTYPE;
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    discovery_exact BOOLEAN;
    observed_at_ms BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    SELECT * INTO issuance
    FROM github_server_service_authority_issuances
    WHERE tenant_id = NEW.tenant_id
      AND authority_id = NEW.authority_id
      AND generation = NEW.generation
    FOR SHARE;
    SELECT * INTO authority
    FROM github_server_service_authorities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.authority_id
    FOR SHARE;
    IF issuance.authority_id IS NULL
        OR authority.id IS NULL
        OR authority.state <> 'active'
        OR authority.current_issuance_generation IS DISTINCT FROM NEW.generation
        OR issuance.state <> 'ready'
        OR issuance.state_updated_at_ms > NEW.granted_at_ms
        OR authority.state_updated_at_ms > NEW.granted_at_ms
        OR NEW.required_through_ms
            > issuance.provider_expires_at_ms - 60000
    THEN
        RAISE EXCEPTION 'GitHub server-service handoff authority is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_handoffs_authority_exact';
    END IF;

    IF authority.service_scope = 'checks_write' THEN
        SELECT * INTO check_outbox
        FROM github_check_projection_outbox
        WHERE subject_id = NEW.consumer_id
        FOR SHARE;
        SELECT * INTO check_subject
        FROM github_check_subjects
        WHERE id = NEW.consumer_id
        FOR SHARE;
        IF check_outbox.subject_id IS NULL
            OR check_subject.id IS NULL
            OR check_outbox.state <> 'claimed'
            OR check_outbox.claim_owner_id <> NEW.consumer_owner_id
            OR check_outbox.claim_fence <> NEW.consumer_claim_fence
            OR check_outbox.claimed_desired_revision <> NEW.consumer_revision
            OR check_outbox.claimed_at_ms IS NULL
            OR check_outbox.claim_expires_at_ms IS NULL
            OR check_outbox.claimed_at_ms > NEW.granted_at_ms
            OR check_outbox.state_updated_at_ms > NEW.granted_at_ms
            OR check_outbox.claim_expires_at_ms <= NEW.granted_at_ms
            OR NEW.required_through_ms::NUMERIC
                > check_outbox.claim_expires_at_ms::NUMERIC
                    + (CASE NEW.consumer_action
                        WHEN 'publish_check_run' THEN 600000
                        ELSE 300000
                    END)
            OR (CASE NEW.consumer_action
                WHEN 'ensure_check_suite' THEN check_outbox.claim_action <> 'ensure_suite'
                WHEN 'create_check_run' THEN check_outbox.claim_action <> 'prepare_run_create'
                WHEN 'reconcile_check_run' THEN check_outbox.claim_action <> 'reconcile_run_create'
                WHEN 'publish_check_run' THEN check_outbox.claim_action <> 'publish'
                ELSE TRUE
            END)
            OR check_subject.tenant_id <> authority.tenant_id
            OR check_subject.repository_id <> authority.repository_id
            OR check_subject.provider_connection_id <> authority.provider_connection_id
            OR check_subject.provider_installation_id <> authority.provider_installation_id
            OR check_subject.github_app_id <> authority.github_app_id
            OR check_subject.github_repository_id <> authority.github_repository_id
            OR check_subject.github_repository_name <> authority.github_repository_name
        THEN
            RAISE EXCEPTION 'GitHub Checks handoff consumer claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_handoffs_checks_claim_exact';
        END IF;
    ELSIF authority.service_scope = 'repository_contents_read' THEN
        IF NEW.consumer_action = 'discover_repository_schedules' THEN
            SELECT EXISTS (
                SELECT 1
                  FROM github_schedule_discovery_claims AS discovery
                  JOIN github_provider_manifest_current AS current
                    ON current.tenant_id = discovery.tenant_id
                   AND current.repository_id = discovery.repository_id
                   AND current.provider_connection_id = discovery.provider_connection_id
                   AND current.manifest_revision = discovery.manifest_revision
                   AND current.manifest_digest = discovery.manifest_digest
                  JOIN github_provider_manifest_revisions AS manifest
                    ON manifest.tenant_id = current.tenant_id
                   AND manifest.repository_id = current.repository_id
                   AND manifest.provider_connection_id = current.provider_connection_id
                   AND manifest.manifest_revision = current.manifest_revision
                   AND manifest.manifest_digest = current.manifest_digest
                  JOIN repositories AS schedule_repository
                    ON schedule_repository.id = discovery.repository_id
                   AND schedule_repository.tenant_id = discovery.tenant_id
                   AND schedule_repository.scm_provider = 'github'
                   AND schedule_repository.provider_repository_id =
                       manifest.github_repository_id::TEXT
                 WHERE discovery.discovery_id = NEW.consumer_id
                   AND discovery.state = 'claimed'
                   AND discovery.claim_owner_id = NEW.consumer_owner_id
                   AND discovery.claim_fence = NEW.consumer_claim_fence
                   AND NEW.consumer_revision = 1
                   AND discovery.claimed_at_ms <= NEW.granted_at_ms
                   AND discovery.updated_at_ms <= NEW.granted_at_ms
                   AND discovery.claim_expires_at_ms > NEW.granted_at_ms
                   AND discovery.claim_expires_at_ms > observed_at_ms
                   AND NEW.required_through_ms::NUMERIC <=
                       discovery.claim_expires_at_ms::NUMERIC + 300000
                   AND discovery.tenant_id = authority.tenant_id
                   AND discovery.repository_id = authority.repository_id
                   AND discovery.provider_connection_id = authority.provider_connection_id
                   AND discovery.source_authority_kind =
                       'repository_contents_read'
                   AND discovery.repository_contents_authority_id = authority.id
                   AND discovery.repository_contents_authority_identity_digest =
                       authority.identity_digest
                   AND discovery.repository_contents_authority_app_configuration_revision =
                       authority.app_configuration_revision
                   AND discovery.repository_contents_authority_policy_revision =
                       authority.policy_revision
                   AND manifest.provider_installation_id =
                       authority.provider_installation_id
                   AND manifest.github_app_id = authority.github_app_id
                   AND manifest.github_repository_id = authority.github_repository_id
                   AND manifest.github_repository_name = authority.github_repository_name
                   AND manifest.github_repository_owner_id IS NOT NULL
                   AND manifest.github_repository_owner_id =
                       discovery.github_repository_owner_id
                 FOR SHARE OF discovery, current, manifest, schedule_repository
            ) INTO discovery_exact;
            IF discovery_exact IS DISTINCT FROM TRUE THEN
                RAISE EXCEPTION 'private GitHub schedule discovery handoff claim is not exact'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT =
                              'github_server_service_handoffs_schedule_discovery_claim_exact';
            END IF;
        ELSE
            SELECT * INTO delivery
            FROM provider_delivery_inbox
            WHERE id = NEW.consumer_id
            FOR SHARE;
            SELECT * INTO repository
            FROM repositories
            WHERE id = authority.repository_id
              AND tenant_id = authority.tenant_id
            FOR SHARE;
            IF delivery.id IS NULL
                OR repository.id IS NULL
                OR delivery.state IS DISTINCT FROM 'claimed'
                OR delivery.claim_owner_id IS DISTINCT FROM NEW.consumer_owner_id
                OR delivery.claim_fence IS DISTINCT FROM NEW.consumer_claim_fence
                OR delivery.attempt_count IS DISTINCT FROM NEW.consumer_revision
                OR delivery.claimed_at_ms IS NULL
                OR delivery.claim_expires_at_ms IS NULL
                OR delivery.claimed_at_ms > NEW.granted_at_ms
                OR delivery.state_updated_at_ms > NEW.granted_at_ms
                OR delivery.claim_expires_at_ms <= NEW.granted_at_ms
                OR NEW.required_through_ms::NUMERIC
                    > delivery.claim_expires_at_ms::NUMERIC + 300000
                OR NEW.consumer_action NOT IN (
                    'fetch_repository_revision',
                    'fetch_repository_changed_files'
                )
                OR delivery.tenant_id IS DISTINCT FROM authority.tenant_id
                OR delivery.provider IS DISTINCT FROM 'github'
                OR delivery.repository_visibility IS DISTINCT FROM 'private'
                OR delivery.connection_id IS DISTINCT FROM authority.provider_connection_id
                OR delivery.installation_id IS DISTINCT FROM authority.provider_installation_id
                OR delivery.provider_repository_id IS DISTINCT FROM authority.github_repository_id
                OR delivery.repository_identity IS DISTINCT FROM authority.github_repository_name
                OR repository.scm_provider IS DISTINCT FROM 'github'
                OR repository.provider_repository_id
                    IS DISTINCT FROM authority.github_repository_id::TEXT
                OR repository.owner || '/' || repository.name
                    IS DISTINCT FROM authority.github_repository_name
            THEN
                RAISE EXCEPTION 'private GitHub source handoff consumer claim is not exact'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_handoffs_source_claim_exact';
            END IF;
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub server-service handoff scope is unknown'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_handoffs_scope_exact';
    END IF;
    RETURN NEW;
END;
$$;
