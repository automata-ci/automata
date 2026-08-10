-- Current-only completion of GitHub job runtime authority after the immutable
-- workflow runtime-policy and provider-manifest chain introduced by 0043.
-- No row from the earlier incomplete identity can be interpreted safely: it
-- omitted the exact App/JWT issuer and had no immutable operation receipts.

-- Configuration fingerprints describe an installation-wide broker policy,
-- while the App/policy revisions are separate immutable authority identity.
-- Multiple exact revisions must remain active while already-admitted work
-- drains, but one revision cannot claim two authorities for the same scope.
DROP INDEX github_server_service_authorities_one_active_scope;

ALTER TABLE github_server_service_authorities
    DROP CONSTRAINT github_server_service_authorities_exact_config_unique,
    ADD CONSTRAINT github_server_service_authorities_exact_config_unique UNIQUE (
        tenant_id, repository_id, provider_connection_id,
        provider_installation_id, service_scope, app_configuration_revision,
        policy_revision, configuration_fingerprint
    );

LOCK TABLE github_runtime_authority_issuances IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM github_runtime_authority_issuances LIMIT 1) THEN
        RAISE EXCEPTION
            'obsolete GitHub runtime-authority state exists; recreate the current-only store'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_v3_current_only_empty_upgrade';
    END IF;
END;
$automata$;

ALTER TABLE github_runtime_authority_issuances
    ADD COLUMN github_app_id BIGINT NOT NULL,
    ADD COLUMN github_app_client_id TEXT COLLATE "C" NOT NULL,
    ADD COLUMN github_app_jwt_issuer_kind TEXT COLLATE "C" NOT NULL,
    ADD COLUMN github_app_jwt_issuer_value TEXT COLLATE "C" NOT NULL,
    ADD COLUMN preparation_selection_id UUID NOT NULL,
    ADD COLUMN preparation_selection_owner_id UUID NOT NULL,
    ADD COLUMN preparation_selection_generation BIGINT NOT NULL,
    ADD COLUMN preparation_selection_descriptor_digest BYTEA NOT NULL,
    ADD COLUMN preparation_selection_claimed_at_ms BIGINT NOT NULL,
    ADD COLUMN preparation_selection_expires_at_ms BIGINT NOT NULL,
    ADD COLUMN activation_selection_id UUID NOT NULL,
    ADD COLUMN activation_selection_owner_id UUID NOT NULL,
    ADD COLUMN activation_selection_generation BIGINT NOT NULL,
    ADD COLUMN activation_selection_input_digest BYTEA NOT NULL,
    ADD COLUMN activation_selection_claimed_at_ms BIGINT NOT NULL,
    ADD COLUMN activation_selection_expires_at_ms BIGINT NOT NULL,
    ADD COLUMN materialization_selection_id UUID NOT NULL,
    ADD COLUMN materialization_selection_owner_id UUID NOT NULL,
    ADD COLUMN materialization_selection_generation BIGINT NOT NULL,
    ADD COLUMN materialization_selection_descriptor_digest BYTEA NOT NULL,
    ADD COLUMN materialization_selection_claimed_at_ms BIGINT NOT NULL,
    ADD COLUMN materialization_selection_expires_at_ms BIGINT NOT NULL,
    ADD COLUMN mint_provider_request_millis BIGINT,
    ADD COLUMN operation_request_kind TEXT COLLATE "C",
    ADD COLUMN operation_request_claim_fence BIGINT,
    ADD COLUMN operation_request_claim_owner_id UUID,
    ADD COLUMN operation_request_observed_at_ms BIGINT,
    ADD COLUMN operation_request_retry_at_ms BIGINT,
    ADD COLUMN operation_request_failure_kind TEXT COLLATE "C",
    ADD COLUMN operation_request_commit_disposition TEXT COLLATE "C",
    ADD COLUMN operation_request_provider_expires_at_ms BIGINT,
    ADD COLUMN operation_request_safe_erase_after_ms BIGINT,
    ADD COLUMN operation_request_plaintext_schema INTEGER,
    ADD COLUMN operation_request_plaintext_size_bytes BIGINT,
    ADD COLUMN operation_request_plaintext_digest BYTEA,
    ADD COLUMN operation_request_aad_digest BYTEA,
    ADD COLUMN operation_request_envelope_digest BYTEA,
    ADD CONSTRAINT github_runtime_authority_policy_is_job_ir CHECK (
        policy_digest = job_ir_digest
    ),
    ADD CONSTRAINT github_runtime_authority_app_identity_shape CHECK (
        github_app_id > 0
        AND octet_length(github_app_client_id) BETWEEN 1 AND 128
        AND github_app_client_id ~ '^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$'
        AND github_app_jwt_issuer_kind IN ('app_client_id', 'app_id')
        AND octet_length(github_app_jwt_issuer_value) BETWEEN 1 AND 128
        AND github_app_jwt_issuer_value ~ '^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$'
        AND github_app_jwt_issuer_value = CASE github_app_jwt_issuer_kind
            WHEN 'app_client_id' THEN github_app_client_id
            WHEN 'app_id' THEN github_app_id::TEXT
        END
    ),
    ADD CONSTRAINT github_runtime_authority_selection_tail_shape CHECK (
        preparation_selection_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND preparation_selection_owner_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND preparation_selection_generation > 0
        AND octet_length(preparation_selection_descriptor_digest) = 32
        AND preparation_selection_claimed_at_ms >= 0
        AND preparation_selection_expires_at_ms >
            preparation_selection_claimed_at_ms
        AND preparation_selection_expires_at_ms -
            preparation_selection_claimed_at_ms <= 900000
        AND activation_selection_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND activation_selection_owner_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND activation_selection_generation > 0
        AND octet_length(activation_selection_input_digest) = 32
        AND activation_selection_claimed_at_ms >= 0
        AND activation_selection_expires_at_ms >
            activation_selection_claimed_at_ms
        AND activation_selection_expires_at_ms -
            activation_selection_claimed_at_ms <= 900000
        AND materialization_selection_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND materialization_selection_owner_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND materialization_selection_generation > 0
        AND octet_length(materialization_selection_descriptor_digest) = 32
        AND materialization_selection_claimed_at_ms >= 0
        AND materialization_selection_expires_at_ms >
            materialization_selection_claimed_at_ms
        AND materialization_selection_expires_at_ms -
            materialization_selection_claimed_at_ms <= 900000
    ),
    ADD CONSTRAINT github_runtime_authority_selection_tail_receipts_fk_preparation
      FOREIGN KEY (preparation_selection_id)
      REFERENCES workflow_plan_v2_activation_work_selections(selection_id)
      ON DELETE RESTRICT,
    ADD CONSTRAINT github_runtime_authority_selection_tail_receipts_fk_activation
      FOREIGN KEY (activation_selection_id)
      REFERENCES workflow_plan_v2_activation_work_selections(selection_id)
      ON DELETE RESTRICT,
    ADD CONSTRAINT github_runtime_authority_selection_tail_receipts_fk_materialization
      FOREIGN KEY (materialization_selection_id)
      REFERENCES workflow_plan_v2_materialization_work_selections(selection_id)
      ON DELETE RESTRICT,
    ADD CONSTRAINT github_runtime_authority_mint_provider_request_shape CHECK (
        (mint_started_at_ms IS NULL AND mint_provider_request_millis IS NULL)
        OR (mint_started_at_ms IS NOT NULL
            AND mint_provider_request_millis BETWEEN 1 AND 120000)
    );

ALTER TABLE github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_operation_request_shape CHECK ((
        operation_request_kind IS NULL
        AND operation_request_claim_fence IS NULL
        AND operation_request_claim_owner_id IS NULL
        AND operation_request_observed_at_ms IS NULL
        AND operation_request_retry_at_ms IS NULL
        AND operation_request_failure_kind IS NULL
        AND operation_request_commit_disposition IS NULL
        AND operation_request_provider_expires_at_ms IS NULL
        AND operation_request_safe_erase_after_ms IS NULL
        AND operation_request_plaintext_schema IS NULL
        AND operation_request_plaintext_size_bytes IS NULL
        AND operation_request_plaintext_digest IS NULL
        AND operation_request_aad_digest IS NULL
        AND operation_request_envelope_digest IS NULL
    ) OR (
        operation_request_kind = 'mint_commit'
        AND operation_request_claim_fence BETWEEN 1 AND 32
        AND operation_request_claim_owner_id IS NOT NULL
        AND operation_request_claim_owner_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND operation_request_observed_at_ms >= 0
        AND operation_request_retry_at_ms IS NULL
        AND operation_request_failure_kind IS NULL
        AND operation_request_commit_disposition IN ('deliverable', 'revoke_only')
        AND (
            operation_request_provider_expires_at_ms IS NULL
            OR operation_request_provider_expires_at_ms > requested_at_ms
        )
        AND operation_request_safe_erase_after_ms IS NOT NULL
        AND operation_request_plaintext_schema = 1
        AND operation_request_plaintext_size_bytes BETWEEN 1 AND 65536
        AND octet_length(operation_request_plaintext_digest) = 32
        AND octet_length(operation_request_aad_digest) = 32
        AND octet_length(operation_request_envelope_digest) = 32
    ) OR (
        operation_request_kind = 'quarantine'
        AND operation_request_claim_fence = 0
        AND operation_request_claim_owner_id IS NULL
        AND operation_request_observed_at_ms >= 0
        AND operation_request_retry_at_ms IS NULL
        AND operation_request_failure_kind IN (
            'invalid_envelope', 'unsupported_envelope_schema',
            'envelope_authentication_failed', 'invalid_wrapped_data_key',
            'unknown_wrapping_key', 'retired_wrapping_key',
            'cryptographic_failure'
        )
        AND operation_request_commit_disposition IS NULL
        AND operation_request_provider_expires_at_ms IS NULL
        AND operation_request_safe_erase_after_ms IS NULL
        AND operation_request_plaintext_schema IS NULL
        AND operation_request_plaintext_size_bytes IS NULL
        AND operation_request_plaintext_digest IS NULL
        AND octet_length(operation_request_aad_digest) = 32
        AND operation_request_envelope_digest IS NULL
    ) OR (
        operation_request_kind IN (
            'revocation_retry', 'revocation_defer', 'revocation_confirm'
        )
        AND operation_request_claim_fence BETWEEN 1 AND 64
        AND operation_request_claim_owner_id IS NOT NULL
        AND operation_request_claim_owner_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND operation_request_observed_at_ms >= 0
        AND (
            operation_request_kind = 'revocation_retry'
            AND operation_request_retry_at_ms >
                operation_request_observed_at_ms
            AND operation_request_failure_kind ~
                '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            OR operation_request_kind = 'revocation_defer'
            AND operation_request_retry_at_ms IS NULL
            AND operation_request_failure_kind ~
                '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            OR operation_request_kind = 'revocation_confirm'
            AND operation_request_retry_at_ms IS NULL
            AND operation_request_failure_kind IS NULL
        )
        AND (
            operation_request_failure_kind IS NULL
            OR octet_length(operation_request_failure_kind) BETWEEN 1 AND 128
        )
        AND operation_request_commit_disposition IS NULL
        AND operation_request_provider_expires_at_ms IS NULL
        AND operation_request_safe_erase_after_ms IS NULL
        AND operation_request_plaintext_schema IS NULL
        AND operation_request_plaintext_size_bytes IS NULL
        AND operation_request_plaintext_digest IS NULL
        AND operation_request_aad_digest IS NULL
        AND operation_request_envelope_digest IS NULL
    ));

CREATE FUNCTION automata_github_runtime_authority_same_operation_request(
    prior github_runtime_authority_issuances,
    candidate github_runtime_authority_issuances
)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
AS $automata$
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
$automata$;

CREATE FUNCTION automata_github_runtime_authority_same_non_operation_state(
    prior github_runtime_authority_issuances,
    candidate github_runtime_authority_issuances
)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
AS $automata$
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
$automata$;

-- Operation request columns are edge-local capture inputs.  Once the edge is
-- durably represented by its transition and reciprocal receipt, an ordinary
-- successor must not inherit and accidentally reinterpret the prior request.
CREATE FUNCTION automata_clear_stale_github_runtime_authority_operation_request()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.operation_request_kind IS NOT NULL
        AND automata_github_runtime_authority_same_operation_request(OLD, NEW)
        AND NOT automata_github_runtime_authority_same_non_operation_state(OLD, NEW)
    THEN
        NEW.operation_request_kind := NULL;
        NEW.operation_request_claim_fence := NULL;
        NEW.operation_request_claim_owner_id := NULL;
        NEW.operation_request_observed_at_ms := NULL;
        NEW.operation_request_retry_at_ms := NULL;
        NEW.operation_request_failure_kind := NULL;
        NEW.operation_request_commit_disposition := NULL;
        NEW.operation_request_provider_expires_at_ms := NULL;
        NEW.operation_request_safe_erase_after_ms := NULL;
        NEW.operation_request_plaintext_schema := NULL;
        NEW.operation_request_plaintext_size_bytes := NULL;
        NEW.operation_request_plaintext_digest := NULL;
        NEW.operation_request_aad_digest := NULL;
        NEW.operation_request_envelope_digest := NULL;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_00z_clear_stale_operation_request
BEFORE UPDATE ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION
    automata_clear_stale_github_runtime_authority_operation_request();

CREATE FUNCTION automata_github_runtime_authority_has_selection_tails(
    authority github_runtime_authority_issuances
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_concrete_jobs AS concrete
        JOIN workflow_plan_v2_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = logical_job.run_id
         AND publication.invocation_id = logical_job.invocation_id
         AND publication.logical_job_id = logical_job.id
         AND publication.activation_input_digest =
             logical_job.activation_input_digest
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.run_id = publication.run_id
         AND preparation.invocation_id = publication.invocation_id
         AND preparation.logical_job_id = publication.logical_job_id
         AND preparation.activation_input_digest =
             publication.activation_input_digest
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = preparation.run_id
         AND preparation_claim.invocation_id = preparation.invocation_id
         AND preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.descriptor_digest = preparation.descriptor_digest
        JOIN workflow_plan_v2_activation_work_selections AS preparation_selection
          ON preparation_selection.selection_id =
             authority.preparation_selection_id
         AND preparation_selection.outcome = 'claimed'
         AND preparation_selection.tenant_id = authority.tenant_id
         AND preparation_selection.run_id = authority.run_id
         AND preparation_selection.invocation_id = concrete.invocation_id
         AND preparation_selection.logical_job_id = concrete.logical_job_id
         AND preparation_selection.authority_kind = 'preparation'
         AND preparation_selection.owner_id =
             authority.preparation_selection_owner_id
         AND preparation_selection.authority_digest =
             authority.preparation_selection_descriptor_digest
        JOIN workflow_plan_v2_activation_work_selections AS activation_selection
          ON activation_selection.selection_id = authority.activation_selection_id
         AND activation_selection.outcome = 'claimed'
         AND activation_selection.tenant_id = authority.tenant_id
         AND activation_selection.run_id = authority.run_id
         AND activation_selection.invocation_id = concrete.invocation_id
         AND activation_selection.logical_job_id = concrete.logical_job_id
         AND activation_selection.authority_kind = 'activation'
         AND activation_selection.owner_id = authority.activation_selection_owner_id
         AND activation_selection.authority_digest =
             authority.activation_selection_input_digest
        JOIN workflow_plan_v2_materialization_work_selections AS materialization_selection
          ON materialization_selection.selection_id =
             authority.materialization_selection_id
         AND materialization_selection.outcome = 'claimed'
         AND materialization_selection.tenant_id = authority.tenant_id
         AND materialization_selection.run_id = authority.run_id
         AND materialization_selection.invocation_id = concrete.invocation_id
         AND materialization_selection.logical_job_id = concrete.logical_job_id
         AND materialization_selection.instance_id = concrete.instance_id
         AND materialization_selection.owner_id =
             authority.materialization_selection_owner_id
         AND materialization_selection.authority_digest =
             authority.materialization_selection_descriptor_digest
        WHERE concrete.job_id = authority.job_id
          AND concrete.run_id = authority.run_id
          AND preparation_claim.origin_selection_id =
              authority.preparation_selection_id
          AND preparation_claim.owner_id =
              authority.preparation_selection_owner_id
          AND preparation_claim.generation =
              authority.preparation_selection_generation
          AND preparation_claim.descriptor_digest =
              authority.preparation_selection_descriptor_digest
          AND preparation_claim.claimed_at_ms =
              authority.preparation_selection_claimed_at_ms
          AND preparation_claim.expires_at_ms =
              authority.preparation_selection_expires_at_ms
          AND logical_job.activation_origin_selection_id =
              authority.activation_selection_id
          AND logical_job.activation_fence = authority.activation_selection_generation
          AND logical_job.activation_input_digest =
              authority.activation_selection_input_digest
          AND publication.activation_owner_id =
              authority.activation_selection_owner_id
          AND publication.activation_generation =
              authority.activation_selection_generation
          AND publication.activation_input_digest =
              authority.activation_selection_input_digest
          AND publication.activation_claimed_at_ms =
              authority.activation_selection_claimed_at_ms
          AND publication.activation_expires_at_ms =
              authority.activation_selection_expires_at_ms
          AND materialization.origin_selection_id =
              authority.materialization_selection_id
          AND materialization.owner_id = authority.materialization_selection_owner_id
          AND materialization.generation = authority.materialization_selection_generation
          AND materialization.descriptor_digest =
              authority.materialization_selection_descriptor_digest
          AND materialization.claimed_at_ms =
              authority.materialization_selection_claimed_at_ms
          AND materialization.expires_at_ms =
              authority.materialization_selection_expires_at_ms
          AND (
              (
                  preparation_selection.generation =
                      authority.preparation_selection_generation
                  AND preparation_selection.claimed_at_ms =
                      authority.preparation_selection_claimed_at_ms
                  AND preparation_selection.expires_at_ms =
                      authority.preparation_selection_expires_at_ms
              ) OR EXISTS (
                  SELECT 1
                  FROM workflow_plan_v2_activation_renewal_receipts AS renewal
                  WHERE renewal.selection_id = authority.preparation_selection_id
                    AND renewal.logical_job_id = concrete.logical_job_id
                    AND renewal.authority_kind = 'preparation'
                    AND renewal.owner_id = authority.preparation_selection_owner_id
                    AND renewal.authority_digest =
                        authority.preparation_selection_descriptor_digest
                    AND renewal.runtime_policy_revision =
                        preparation_claim.runtime_policy_revision
                    AND renewal.runtime_policy_digest =
                        preparation_claim.runtime_policy_digest
                    AND renewal.successor_generation =
                        authority.preparation_selection_generation
                    AND renewal.successor_claimed_at_ms =
                        authority.preparation_selection_claimed_at_ms
                    AND renewal.successor_expires_at_ms =
                        authority.preparation_selection_expires_at_ms
              )
          )
          AND (
              (
                  activation_selection.generation =
                      authority.activation_selection_generation
                  AND activation_selection.claimed_at_ms =
                      authority.activation_selection_claimed_at_ms
                  AND activation_selection.expires_at_ms =
                      authority.activation_selection_expires_at_ms
              ) OR EXISTS (
                  SELECT 1
                  FROM workflow_plan_v2_activation_renewal_receipts AS renewal
                  WHERE renewal.selection_id = authority.activation_selection_id
                    AND renewal.logical_job_id = concrete.logical_job_id
                    AND renewal.authority_kind = 'activation'
                    AND renewal.owner_id = authority.activation_selection_owner_id
                    AND renewal.authority_digest =
                        authority.activation_selection_input_digest
                    AND renewal.runtime_policy_revision =
                        logical_job.runtime_policy_revision
                    AND renewal.runtime_policy_digest =
                        logical_job.runtime_policy_digest
                    AND renewal.successor_generation =
                        authority.activation_selection_generation
                    AND renewal.successor_claimed_at_ms =
                        authority.activation_selection_claimed_at_ms
                    AND renewal.successor_expires_at_ms =
                        authority.activation_selection_expires_at_ms
              )
          )
          AND (
              (
                  materialization_selection.generation =
                      authority.materialization_selection_generation
                  AND materialization_selection.claimed_at_ms =
                      authority.materialization_selection_claimed_at_ms
                  AND materialization_selection.expires_at_ms =
                      authority.materialization_selection_expires_at_ms
              ) OR EXISTS (
                  SELECT 1
                  FROM workflow_plan_v2_materialization_renewal_receipts AS renewal
                  WHERE renewal.selection_id = authority.materialization_selection_id
                    AND renewal.instance_id = concrete.instance_id
                    AND renewal.owner_id =
                        authority.materialization_selection_owner_id
                    AND renewal.authority_digest =
                        authority.materialization_selection_descriptor_digest
                    AND renewal.runtime_policy_revision =
                        materialization.runtime_policy_revision
                    AND renewal.runtime_policy_digest =
                        materialization.runtime_policy_digest
                    AND renewal.expected_job_id = concrete.job_id
                    AND renewal.expected_attempt_id = concrete.initial_attempt_id
                    AND renewal.successor_generation =
                        authority.materialization_selection_generation
                    AND renewal.successor_claimed_at_ms =
                        authority.materialization_selection_claimed_at_ms
                    AND renewal.successor_expires_at_ms =
                        authority.materialization_selection_expires_at_ms
              )
          )
    )
$automata$;

-- Retain the 0041 mutable-execution predicate as one half of currentness, then
-- close it over the immutable 0043 manifest -> runtime-policy pin -> runner
-- policy and the exact App/JWT issuer admitted for this issuance.
ALTER FUNCTION automata_github_runtime_authority_is_current(
    github_runtime_authority_issuances, BIGINT
) RENAME TO automata_github_runtime_authority_v2_base_is_current;

CREATE FUNCTION automata_github_runtime_authority_has_v3_provenance(
    authority github_runtime_authority_issuances
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT automata_github_runtime_authority_has_selection_tails(authority)
       AND EXISTS (
        SELECT 1
        FROM github_workflow_run_subject_evidence AS subject
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery.tenant_id
         AND manifest.repository_id = delivery.repository_id
         AND manifest.provider_connection_id = delivery.provider_connection_id
         AND manifest.manifest_revision = delivery.provider_manifest_revision
         AND manifest.manifest_digest = delivery.provider_manifest_digest
        JOIN github_server_service_authorities AS checks
          ON checks.tenant_id = delivery.tenant_id
         AND checks.id = delivery.checks_authority_id
         AND checks.repository_id = delivery.repository_id
         AND checks.provider_connection_id = delivery.provider_connection_id
         AND checks.provider_installation_id = delivery.provider_installation_id
         AND checks.github_repository_id = delivery.github_repository_id
         AND checks.github_repository_name = delivery.github_repository_name
         AND checks.service_scope = 'checks_write'
         AND checks.identity_digest = delivery.checks_authority_identity_digest
         AND checks.app_configuration_revision =
             delivery.checks_authority_app_configuration_revision
         AND checks.policy_revision = delivery.checks_authority_policy_revision
        JOIN workflow_plan_v2_runtime_policy_pins AS pin
          ON pin.run_id = subject.run_id
         AND pin.tenant_id = subject.tenant_id
         AND pin.repository_id = subject.repository_id
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
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.run_id = publication.run_id
         AND preparation.invocation_id = publication.invocation_id
         AND preparation.logical_job_id = publication.logical_job_id
         AND preparation.activation_input_digest = publication.activation_input_digest
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = preparation.run_id
         AND preparation_claim.invocation_id = preparation.invocation_id
         AND preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.descriptor_digest = preparation.descriptor_digest
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        WHERE subject.tenant_id = authority.tenant_id
          AND subject.repository_id = authority.repository_id
          AND subject.run_id = authority.run_id
          AND delivery.provider_connection_id = authority.provider_connection_id
          AND delivery.provider_installation_id = authority.provider_installation_id
          AND delivery.github_repository_id = authority.github_repository_id
          AND delivery.github_repository_name = authority.github_repository_name
          AND manifest.github_app_id = authority.github_app_id
          AND manifest.github_app_client_id = authority.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind = authority.github_app_jwt_issuer_kind
          AND authority.github_app_jwt_issuer_value = CASE manifest.github_app_jwt_issuer_kind
              WHEN 'app_client_id' THEN manifest.github_app_client_id
              WHEN 'app_id' THEN manifest.github_app_id::TEXT
          END
          AND manifest.app_key_spki_sha256 = authority.issuer_fingerprint
          AND manifest.github_app_id = checks.github_app_id
          AND manifest.github_app_client_id = checks.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind = checks.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = checks.app_key_spki_sha256
          AND manifest.app_configuration_revision = checks.app_configuration_revision
          AND manifest.policy_revision = checks.policy_revision
          AND checks.configuration_fingerprint = authority.configuration_fingerprint
          AND manifest.runtime_policy_revision = pin.policy_revision
          AND manifest.runtime_policy_digest = pin.policy_digest
          AND manifest.runner_policy_digest = pg_catalog.sha256(policy.canonical_policy)
          AND manifest.runner_policy_object_key = 'github/runner-policy/v1/'
              || pg_catalog.encode(manifest.runner_policy_digest, 'hex') || '.json'
          AND manifest.runner_policy_size_bytes = pg_catalog.octet_length(policy.canonical_policy)
          AND manifest.runner_policy_media_type =
              'application/vnd.automata.github-runner-policy+json'
          AND logical_job.runtime_policy_revision = pin.policy_revision
          AND logical_job.runtime_policy_digest = pin.policy_digest
          AND preparation_claim.runtime_policy_revision = pin.policy_revision
          AND preparation_claim.runtime_policy_digest = pin.policy_digest
          AND preparation_claim.runner_policy_digest = manifest.runner_policy_digest
          AND preparation_claim.runner_policy_object_key = manifest.runner_policy_object_key
          AND preparation_claim.runner_policy_size_bytes = manifest.runner_policy_size_bytes
          AND preparation_claim.runner_policy_media_type = manifest.runner_policy_media_type
          AND preparation.runtime_policy_revision = pin.policy_revision
          AND preparation.runtime_policy_digest = pin.policy_digest
          AND publication.runtime_policy_revision = pin.policy_revision
          AND publication.runtime_policy_digest = pin.policy_digest
          AND instance.runtime_policy_revision = pin.policy_revision
          AND instance.runtime_policy_digest = pin.policy_digest
          AND materialization.runtime_policy_revision = pin.policy_revision
          AND materialization.runtime_policy_digest = pin.policy_digest
          AND concrete.runtime_policy_revision = pin.policy_revision
          AND concrete.runtime_policy_digest = pin.policy_digest
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND publication.authority_profile = 'standard'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
    )
$automata$;

CREATE FUNCTION automata_github_runtime_authority_is_current(
    authority github_runtime_authority_issuances,
    observed_at BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT automata_github_runtime_authority_v2_base_is_current(authority, observed_at)
       AND automata_github_runtime_authority_has_v3_provenance(authority)
$automata$;

CREATE FUNCTION automata_validate_github_runtime_authority_v3_identity()
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
    FOR SHARE OF attempt, job, run, repository, workflow, snapshot, runner, session;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub runtime authority lacks exact execution provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_v3_execution_provenance';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM github_workflow_run_subject_evidence AS subject
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        JOIN workflow_admission_receipts AS admission
          ON admission.tenant_id = subject.tenant_id
         AND admission.idempotency_kind = 'provider_delivery'
         AND admission.idempotency_key = subject.provider_delivery_idempotency_key
         AND admission.request_digest = subject.logical_admission_digest
         AND admission.repository_id = subject.repository_id
         AND admission.run_id = subject.run_id
         AND admission.committed_at_ms = subject.admitted_at_ms
         AND admission.github_subject_evidence_required
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery.tenant_id
         AND manifest.repository_id = delivery.repository_id
         AND manifest.provider_connection_id = delivery.provider_connection_id
         AND manifest.manifest_revision = delivery.provider_manifest_revision
         AND manifest.manifest_digest = delivery.provider_manifest_digest
        JOIN github_server_service_authorities AS checks
          ON checks.tenant_id = delivery.tenant_id
         AND checks.id = delivery.checks_authority_id
         AND checks.repository_id = delivery.repository_id
         AND checks.provider_connection_id = delivery.provider_connection_id
         AND checks.provider_installation_id = delivery.provider_installation_id
         AND checks.github_repository_id = delivery.github_repository_id
         AND checks.github_repository_name = delivery.github_repository_name
         AND checks.service_scope = 'checks_write'
         AND checks.identity_digest = delivery.checks_authority_identity_digest
         AND checks.app_configuration_revision =
             delivery.checks_authority_app_configuration_revision
         AND checks.policy_revision = delivery.checks_authority_policy_revision
        JOIN workflow_plan_v2_runtime_policy_pins AS pin
          ON pin.run_id = subject.run_id
         AND pin.tenant_id = subject.tenant_id
         AND pin.repository_id = subject.repository_id
        JOIN workflow_runtime_policy_revisions AS policy
          ON policy.tenant_id = pin.tenant_id
         AND policy.repository_id = pin.repository_id
         AND policy.policy_revision = pin.policy_revision
         AND policy.policy_digest = pin.policy_digest
         AND policy.state = 'sealed'
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.job_id = NEW.job_id
         AND concrete.run_id = NEW.run_id
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
        JOIN workflow_plan_v2_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.run_id = publication.run_id
         AND preparation.invocation_id = publication.invocation_id
         AND preparation.logical_job_id = publication.logical_job_id
         AND preparation.activation_input_digest = publication.activation_input_digest
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
        WHERE subject.tenant_id = NEW.tenant_id
          AND subject.repository_id = NEW.repository_id
          AND subject.run_id = NEW.run_id
          AND delivery.provider_connection_id = NEW.provider_connection_id
          AND delivery.provider_installation_id = NEW.provider_installation_id
          AND delivery.github_repository_id = NEW.github_repository_id
          AND delivery.github_repository_name = NEW.github_repository_name
          AND manifest.github_app_id = NEW.github_app_id
          AND manifest.github_app_client_id = NEW.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind = NEW.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = NEW.issuer_fingerprint
          AND manifest.github_app_id = checks.github_app_id
          AND manifest.github_app_client_id = checks.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind = checks.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = checks.app_key_spki_sha256
          AND manifest.app_configuration_revision = checks.app_configuration_revision
          AND manifest.policy_revision = checks.policy_revision
          AND checks.configuration_fingerprint = NEW.configuration_fingerprint
          AND manifest.runtime_policy_revision = pin.policy_revision
          AND manifest.runtime_policy_digest = pin.policy_digest
          AND manifest.runner_policy_digest = pg_catalog.sha256(policy.canonical_policy)
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
          AND preparation_claim.runner_policy_digest = manifest.runner_policy_digest
          AND preparation_claim.runner_policy_object_key = manifest.runner_policy_object_key
          AND preparation_claim.runner_policy_size_bytes = manifest.runner_policy_size_bytes
          AND preparation_claim.runner_policy_media_type = manifest.runner_policy_media_type
          AND preparation.runtime_policy_revision = pin.policy_revision
          AND preparation.runtime_policy_digest = pin.policy_digest
          AND publication.runtime_policy_revision = pin.policy_revision
          AND publication.runtime_policy_digest = pin.policy_digest
          AND instance.runtime_policy_revision = pin.policy_revision
          AND instance.runtime_policy_digest = pin.policy_digest
          AND materialization.runtime_policy_revision = pin.policy_revision
          AND materialization.runtime_policy_digest = pin.policy_digest
          AND concrete.runtime_policy_revision = pin.policy_revision
          AND concrete.runtime_policy_digest = pin.policy_digest
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND publication.authority_profile = 'standard'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
          AND (
              delivery.repository_visibility = 'public'
              AND delivery.private_source_authority_id IS NULL
              OR delivery.repository_visibility = 'private'
              AND delivery.private_source_authority_id IS NOT NULL
          )
        FOR SHARE OF subject, delivery, admission, manifest, checks, pin, policy,
                     concrete, materialization, instance, publication, preparation,
                     preparation_claim, logical_job, invocation, marker
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority lacks exact historical policy provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_v3_historical_provenance';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM github_workflow_run_subject_evidence AS subject
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        WHERE subject.tenant_id = NEW.tenant_id
          AND subject.repository_id = NEW.repository_id
          AND subject.run_id = NEW.run_id
          AND delivery.repository_visibility = 'private'
    ) THEN
        PERFORM 1
        FROM github_workflow_run_subject_evidence AS subject
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery.tenant_id
         AND manifest.repository_id = delivery.repository_id
         AND manifest.provider_connection_id = delivery.provider_connection_id
         AND manifest.manifest_revision = delivery.provider_manifest_revision
         AND manifest.manifest_digest = delivery.provider_manifest_digest
        JOIN github_server_service_authorities AS private_authority
          ON private_authority.tenant_id = delivery.tenant_id
         AND private_authority.id = delivery.private_source_authority_id
         AND private_authority.repository_id = delivery.repository_id
         AND private_authority.provider_connection_id = delivery.provider_connection_id
         AND private_authority.provider_installation_id = delivery.provider_installation_id
         AND private_authority.github_repository_id = delivery.github_repository_id
         AND private_authority.github_repository_name = delivery.github_repository_name
         AND private_authority.service_scope = 'private_repository_source_read'
         AND private_authority.github_app_id = manifest.github_app_id
         AND private_authority.github_app_client_id = manifest.github_app_client_id
         AND private_authority.github_app_jwt_issuer_kind =
             manifest.github_app_jwt_issuer_kind
         AND private_authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
         AND private_authority.app_configuration_revision =
             delivery.private_source_authority_app_configuration_revision
         AND private_authority.app_configuration_revision = manifest.app_configuration_revision
         AND private_authority.policy_revision =
             delivery.private_source_authority_policy_revision
         AND private_authority.policy_revision = manifest.policy_revision
         AND private_authority.identity_digest =
             delivery.private_source_authority_identity_digest
        WHERE subject.tenant_id = NEW.tenant_id
          AND subject.repository_id = NEW.repository_id
          AND subject.run_id = NEW.run_id
          AND delivery.provider_connection_id = NEW.provider_connection_id
          AND delivery.provider_installation_id = NEW.provider_installation_id
          AND delivery.github_repository_id = NEW.github_repository_id
          AND delivery.github_repository_name = NEW.github_repository_name
          AND manifest.github_app_id = NEW.github_app_id
          AND manifest.github_app_client_id = NEW.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind = NEW.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = NEW.issuer_fingerprint
        FOR SHARE OF manifest, private_authority;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'GitHub runtime authority lacks exact private-source provenance'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_private_provenance';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_00_v3_identity_guard
BEFORE INSERT ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION automata_validate_github_runtime_authority_v3_identity();

CREATE TRIGGER github_runtime_authority_00_v3_graph_guard_update
BEFORE UPDATE ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION automata_validate_github_runtime_authority_v3_identity();

CREATE FUNCTION automata_guard_github_runtime_authority_v3_database_time()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    IF NEW.state_updated_at_ms > database_now THEN
        RAISE EXCEPTION 'GitHub runtime-authority state time is ahead of PostgreSQL time'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_v3_database_time';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'claimed'
            OR NEW.mint_claimed_at_ms > database_now
            OR NEW.mint_claim_expires_at_ms <= database_now
            OR NEW.state_updated_at_ms <> NEW.mint_claimed_at_ms
            OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority claim is not current at PostgreSQL time'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_insert_database_time';
        END IF;
        RETURN NEW;
    END IF;

    -- A terminal receipt observation does not advance lifecycle time.  Its
    -- exact database-time eligibility is re-proved by the trigger-owned
    -- operation transition after the lifecycle guard proves it is otherwise
    -- a byte-for-byte self transition.
    IF OLD.state = NEW.state
        AND NEW.operation_request_kind IS NOT NULL
        AND automata_github_runtime_authority_same_non_operation_state(
            OLD, NEW
        )
    THEN
        RETURN NEW;
    END IF;

    IF NEW.state = 'claimed' AND OLD.state IN ('claimed', 'mint_retry_pending') THEN
        IF NEW.mint_claimed_at_ms > database_now
            OR NEW.mint_claim_expires_at_ms <= database_now
            OR (
                OLD.state = 'claimed'
                AND OLD.mint_claim_expires_at_ms > database_now
            )
            OR (
                OLD.state = 'mint_retry_pending'
                AND OLD.next_mint_at_ms > database_now
            )
            OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority mint claim is not due and live'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_mint_claim_database_time';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'minting' THEN
        IF OLD.mint_claimed_at_ms > database_now
            OR OLD.mint_claim_expires_at_ms <= database_now
            OR NEW.mint_started_at_ms > database_now
            OR NEW.mint_provider_request_millis NOT BETWEEN 1 AND 120000
            OR database_now::NUMERIC + NEW.mint_provider_request_millis::NUMERIC
                > OLD.mint_claim_expires_at_ms::NUMERIC
            OR database_now::NUMERIC + NEW.mint_provider_request_millis::NUMERIC
                > NEW.request_deadline_at_ms::NUMERIC
            OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority mint begin lacks a live database claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_mint_begin_database_time';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'mint_retry_pending' THEN
        IF NEW.next_mint_at_ms <= database_now
            OR NEW.request_deadline_at_ms <= NEW.next_mint_at_ms
            OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority retry is not current at PostgreSQL time'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_mint_retry_database_time';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'indeterminate' THEN
        IF NEW.indeterminate_at_ms > database_now
            OR NEW.conservative_expiry_at_ms <= database_now
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority indeterminate boundary is expired'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_indeterminate_database_time';
        END IF;
    ELSIF OLD.state IN ('minting', 'indeterminate')
          AND NEW.state IN ('ready', 'revoke_pending') THEN
        IF NEW.safe_erase_after_ms <= database_now
            OR (
                NEW.state = 'ready'
                AND (
                    OLD.state <> 'minting'
                    OR NEW.ready_at_ms > database_now
                    OR NEW.provider_expires_at_ms::NUMERIC
                        <= database_now::NUMERIC + 60000
                    OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
                )
            )
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority finalization is stale at PostgreSQL time'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_finalize_database_time';
        END IF;
    ELSIF OLD.state = 'ready' AND NEW.state = 'revoke_pending' THEN
        IF NEW.safe_erase_after_ms <= database_now
            OR automata_github_runtime_authority_is_current(OLD, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority revocation transition is not due'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_revoke_pending_database_time';
        END IF;
    ELSIF OLD.state IN ('ready', 'revoke_pending') AND NEW.state = 'quarantined' THEN
        IF NEW.quarantine_at_ms > database_now
            OR NEW.safe_erase_after_ms <= database_now
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority quarantine is past safe custody'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_quarantine_database_time';
        END IF;
    ELSIF OLD.state = 'revoke_pending' AND NEW.state = 'revoke_pending' THEN
        IF OLD.revoke_claim_owner_id IS NULL AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF OLD.next_revoke_at_ms > database_now
                OR NEW.revoke_claimed_at_ms > database_now
                OR NEW.revoke_claim_expires_at_ms <= database_now
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
            THEN
                RAISE EXCEPTION 'GitHub runtime-authority revoke claim is not due and live'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_v3_revoke_claim_database_time';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
              AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF OLD.revoke_claim_expires_at_ms > database_now
                OR NEW.revoke_claimed_at_ms > database_now
                OR NEW.revoke_claim_expires_at_ms <= database_now
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
            THEN
                RAISE EXCEPTION 'GitHub runtime-authority revoke takeover is not due and live'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_v3_revoke_takeover_database_time';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
              AND NEW.revoke_claim_owner_id IS NULL THEN
            IF NEW.last_revoke_failure_kind = 'claim_budget_exhausted' THEN
                IF OLD.revoke_claim_expires_at_ms > database_now
                    OR NOT (
                        OLD.revoke_attempt_count = 64
                        OR OLD.revoke_claim_fence = 9223372036854775807
                    )
                THEN
                    RAISE EXCEPTION 'GitHub runtime-authority revoke budget is not exhausted'
                        USING ERRCODE = 'check_violation',
                              CONSTRAINT =
                                  'github_runtime_authority_v3_revoke_budget_database_time';
                END IF;
            ELSIF OLD.revoke_claimed_at_ms > database_now
                OR OLD.revoke_claim_expires_at_ms <= database_now
            THEN
                RAISE EXCEPTION 'GitHub runtime-authority revoke outcome lacks a live claim'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_v3_revoke_outcome_database_time';
            END IF;
        END IF;
    ELSIF NEW.state = 'revoked' THEN
        IF NEW.terminal_reason = 'provider_revocation_confirmed' AND (
                OLD.revoke_claimed_at_ms > database_now
                OR OLD.revoke_claim_expires_at_ms <= database_now
            )
            OR NEW.terminal_reason IN (
                'provider_authority_expired', 'conservative_authority_expired',
                'quarantined_authority_expired'
            ) AND OLD.safe_erase_after_ms > database_now
            OR NEW.terminal_reason = 'indeterminate_authority_expired'
                AND OLD.conservative_expiry_at_ms > database_now
            OR NEW.terminal_reason = 'superseded_before_mint'
                AND automata_github_runtime_authority_is_current(OLD, database_now)
            OR NEW.terminal_reason = 'request_expired_before_mint'
                AND OLD.request_deadline_at_ms > database_now
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority terminal transition is not due'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_v3_terminal_database_time';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_01_v3_database_time_guard
BEFORE INSERT OR UPDATE ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION automata_guard_github_runtime_authority_v3_database_time();

-- Replace the 0023 lifecycle guard rather than stacking a partial exception
-- beside it. The v3 guard retains every immutable identity/history and exact
-- fence rule, adds the App/JWT identity, and admits only two terminal custody
-- paths that 0023 could not represent: a token already past its safe horizon
-- when commit custody returns, and a quarantine request that reaches the same
-- horizon while its row lock is held. Both remain gated by the preceding
-- graph and PostgreSQL-time triggers.
DROP TRIGGER github_runtime_authority_lifecycle_guard
    ON github_runtime_authority_issuances;
DROP FUNCTION automata_enforce_github_runtime_authority_lifecycle();

CREATE FUNCTION automata_enforce_github_runtime_authority_v3_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
        OR NEW.fencing_token IS DISTINCT FROM OLD.fencing_token
        OR NEW.lease_id IS DISTINCT FROM OLD.lease_id
        OR NEW.lease_issued_at_ms IS DISTINCT FROM OLD.lease_issued_at_ms
        OR NEW.lease_expires_at_ms IS DISTINCT FROM OLD.lease_expires_at_ms
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.runner_id IS DISTINCT FROM OLD.runner_id
        OR NEW.runner_session_id IS DISTINCT FROM OLD.runner_session_id
        OR NEW.runner_session_epoch IS DISTINCT FROM OLD.runner_session_epoch
        OR NEW.runner_generation IS DISTINCT FROM OLD.runner_generation
        OR NEW.runner_slot IS DISTINCT FROM OLD.runner_slot
        OR NEW.job_ir_schema IS DISTINCT FROM OLD.job_ir_schema
        OR NEW.job_ir_size_bytes IS DISTINCT FROM OLD.job_ir_size_bytes
        OR NEW.job_ir_digest IS DISTINCT FROM OLD.job_ir_digest
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.provider_installation_id IS DISTINCT FROM OLD.provider_installation_id
        OR NEW.github_app_id IS DISTINCT FROM OLD.github_app_id
        OR NEW.github_app_client_id IS DISTINCT FROM OLD.github_app_client_id
        OR NEW.github_app_jwt_issuer_kind IS DISTINCT FROM OLD.github_app_jwt_issuer_kind
        OR NEW.github_app_jwt_issuer_value IS DISTINCT FROM OLD.github_app_jwt_issuer_value
        OR NEW.github_repository_id IS DISTINCT FROM OLD.github_repository_id
        OR NEW.github_repository_name IS DISTINCT FROM OLD.github_repository_name
        OR NEW.authority_namespace IS DISTINCT FROM OLD.authority_namespace
        OR NEW.policy_digest IS DISTINCT FROM OLD.policy_digest
        OR NEW.issuer_fingerprint IS DISTINCT FROM OLD.issuer_fingerprint
        OR NEW.configuration_fingerprint IS DISTINCT FROM OLD.configuration_fingerprint
        OR NEW.preparation_selection_id IS DISTINCT FROM OLD.preparation_selection_id
        OR NEW.preparation_selection_owner_id IS DISTINCT FROM
            OLD.preparation_selection_owner_id
        OR NEW.preparation_selection_generation IS DISTINCT FROM
            OLD.preparation_selection_generation
        OR NEW.preparation_selection_descriptor_digest IS DISTINCT FROM
            OLD.preparation_selection_descriptor_digest
        OR NEW.preparation_selection_claimed_at_ms IS DISTINCT FROM
            OLD.preparation_selection_claimed_at_ms
        OR NEW.preparation_selection_expires_at_ms IS DISTINCT FROM
            OLD.preparation_selection_expires_at_ms
        OR NEW.activation_selection_id IS DISTINCT FROM OLD.activation_selection_id
        OR NEW.activation_selection_owner_id IS DISTINCT FROM
            OLD.activation_selection_owner_id
        OR NEW.activation_selection_generation IS DISTINCT FROM
            OLD.activation_selection_generation
        OR NEW.activation_selection_input_digest IS DISTINCT FROM
            OLD.activation_selection_input_digest
        OR NEW.activation_selection_claimed_at_ms IS DISTINCT FROM
            OLD.activation_selection_claimed_at_ms
        OR NEW.activation_selection_expires_at_ms IS DISTINCT FROM
            OLD.activation_selection_expires_at_ms
        OR NEW.materialization_selection_id IS DISTINCT FROM
            OLD.materialization_selection_id
        OR NEW.materialization_selection_owner_id IS DISTINCT FROM
            OLD.materialization_selection_owner_id
        OR NEW.materialization_selection_generation IS DISTINCT FROM
            OLD.materialization_selection_generation
        OR NEW.materialization_selection_descriptor_digest IS DISTINCT FROM
            OLD.materialization_selection_descriptor_digest
        OR NEW.materialization_selection_claimed_at_ms IS DISTINCT FROM
            OLD.materialization_selection_claimed_at_ms
        OR NEW.materialization_selection_expires_at_ms IS DISTINCT FROM
            OLD.materialization_selection_expires_at_ms
        OR NEW.requested_at_ms IS DISTINCT FROM OLD.requested_at_ms
        OR NEW.request_deadline_at_ms IS DISTINCT FROM OLD.request_deadline_at_ms
        OR NEW.conservative_expiry_at_ms IS DISTINCT FROM OLD.conservative_expiry_at_ms
    THEN
        RAISE EXCEPTION 'GitHub runtime authority immutable identity cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_v3_identity_immutable';
    END IF;

    IF NEW.state_updated_at_ms < OLD.state_updated_at_ms THEN
        RAISE EXCEPTION 'GitHub runtime authority state time cannot regress'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_time_regression';
    END IF;

    IF OLD.safe_erase_after_ms IS NOT NULL AND (
        NEW.provider_expires_at_ms IS DISTINCT FROM OLD.provider_expires_at_ms
        OR NEW.safe_erase_after_ms IS DISTINCT FROM OLD.safe_erase_after_ms
        OR NEW.commit_disposition IS DISTINCT FROM OLD.commit_disposition
        OR NEW.plaintext_schema IS DISTINCT FROM OLD.plaintext_schema
        OR NEW.plaintext_size_bytes IS DISTINCT FROM OLD.plaintext_size_bytes
        OR NEW.plaintext_digest IS DISTINCT FROM OLD.plaintext_digest
        OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority protected metadata cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_protected_metadata_immutable';
    END IF;

    IF NOT (
            OLD.state IN ('claimed', 'mint_retry_pending')
            AND NEW.state = 'claimed'
        ) AND (
            NEW.mint_attempt_count IS DISTINCT FROM OLD.mint_attempt_count
            OR NEW.mint_claim_fence IS DISTINCT FROM OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.mint_claimed_at_ms IS DISTINCT FROM OLD.mint_claimed_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority mint claim history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_history_immutable';
    END IF;

    IF (
        NEW.mint_started_at_ms IS DISTINCT FROM OLD.mint_started_at_ms
        OR NEW.mint_provider_request_millis IS DISTINCT FROM
            OLD.mint_provider_request_millis
    )
        AND NOT (
            (
                OLD.state = 'claimed'
                AND NEW.state = 'minting'
                AND NEW.mint_started_at_ms IS NOT NULL
                AND NEW.mint_provider_request_millis BETWEEN 1 AND 120000
            )
            OR (
                OLD.state = 'mint_retry_pending'
                AND NEW.state = 'claimed'
                AND NEW.mint_started_at_ms IS NULL
                AND NEW.mint_provider_request_millis IS NULL
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority mint boundary history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_boundary_immutable';
    END IF;

    IF (
            NEW.next_mint_at_ms IS DISTINCT FROM OLD.next_mint_at_ms
            AND NOT (
                (OLD.state = 'minting' AND NEW.state = 'mint_retry_pending')
                OR (
                    OLD.state = 'mint_retry_pending'
                    AND NEW.state IN ('claimed', 'rejected')
                )
            )
        ) OR (
            NEW.last_mint_rejection_kind
                IS DISTINCT FROM OLD.last_mint_rejection_kind
            AND NOT (
                OLD.state = 'minting'
                AND NEW.state IN ('mint_retry_pending', 'rejected')
            )
        ) OR (
            NEW.rejected_at_ms IS DISTINCT FROM OLD.rejected_at_ms
            AND NOT (
                OLD.state IN ('minting', 'mint_retry_pending')
                AND NEW.state = 'rejected'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority rejection history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_rejection_history_immutable';
    END IF;

    IF (
            NEW.indeterminate_at_ms IS DISTINCT FROM OLD.indeterminate_at_ms
            AND NOT (OLD.state = 'minting' AND NEW.state = 'indeterminate')
        ) OR (
            NEW.ready_at_ms IS DISTINCT FROM OLD.ready_at_ms
            AND NOT (OLD.state = 'minting' AND NEW.state = 'ready')
        ) OR (
            NEW.revoke_pending_at_ms IS DISTINCT FROM OLD.revoke_pending_at_ms
            AND NOT (
                OLD.state IN ('minting', 'indeterminate') AND (
                    NEW.state = 'revoke_pending'
                    OR NEW.state = 'revoked'
                    AND NEW.terminal_reason IN (
                        'provider_authority_expired',
                        'conservative_authority_expired'
                    )
                )
                OR OLD.state = 'ready' AND NEW.state = 'revoke_pending'
            )
        ) OR (
            (
                NEW.quarantine_at_ms IS DISTINCT FROM OLD.quarantine_at_ms
                OR NEW.quarantine_kind IS DISTINCT FROM OLD.quarantine_kind
            )
            AND NOT (
                OLD.state IN ('ready', 'revoke_pending')
                AND (
                    NEW.state = 'quarantined'
                    OR NEW.state = 'revoked'
                    AND NEW.terminal_reason = 'quarantined_authority_expired'
                )
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority lifecycle history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_lifecycle_history_immutable';
    END IF;

    IF NOT (OLD.state = 'revoke_pending' AND NEW.state = 'revoke_pending') AND (
        NEW.revoke_attempt_count IS DISTINCT FROM OLD.revoke_attempt_count
        OR NEW.revoke_claim_fence IS DISTINCT FROM OLD.revoke_claim_fence
        OR NEW.last_revoke_failure_kind IS DISTINCT FROM OLD.last_revoke_failure_kind
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority revocation history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_revoke_history_immutable';
    END IF;

    IF OLD.envelope_schema IS NOT NULL AND NEW.state <> 'revoked' AND (
        NEW.envelope_schema IS DISTINCT FROM OLD.envelope_schema
        OR NEW.wrapping_key_id IS DISTINCT FROM OLD.wrapping_key_id
        OR NEW.wrapped_data_key IS DISTINCT FROM OLD.wrapped_data_key
        OR NEW.nonce IS DISTINCT FROM OLD.nonce
        OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority envelope cannot change before erasure'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_envelope_immutable';
    END IF;

    IF NEW.operation_request_kind IS NOT NULL
        AND NOT automata_github_runtime_authority_same_non_operation_state(
            OLD, NEW
        )
        AND NOT (
            OLD.state IN ('minting', 'indeterminate')
            AND NEW.state IN ('ready', 'revoke_pending', 'revoked')
            AND OLD.safe_erase_after_ms IS NULL
            AND NEW.safe_erase_after_ms IS NOT NULL
            OR OLD.state IN ('ready', 'revoke_pending')
            AND NEW.state IN ('quarantined', 'revoked')
            AND NEW.quarantine_at_ms IS DISTINCT FROM OLD.quarantine_at_ms
            OR OLD.state = 'revoke_pending'
            AND OLD.revoke_claim_owner_id IS NOT NULL
            AND (
                NEW.state = 'revoked'
                AND NEW.terminal_reason = 'provider_revocation_confirmed'
                OR NEW.state = 'revoke_pending'
                AND NEW.revoke_claim_owner_id IS NULL
                AND NEW.last_revoke_failure_kind <> 'claim_budget_exhausted'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub operation request may only describe its exact lifecycle edge'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_operation_observation_exact';
    END IF;

    IF OLD.state = NEW.state
        AND NEW.operation_request_kind IS NOT NULL
        AND automata_github_runtime_authority_same_non_operation_state(
            OLD, NEW
        )
    THEN
        NULL;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'claimed' THEN
        IF NEW.mint_attempt_count <> OLD.mint_attempt_count + 1
            OR NEW.mint_claim_fence <> OLD.mint_claim_fence + 1
            OR NEW.mint_claimed_at_ms < OLD.mint_claim_expires_at_ms
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.mint_claimed_at_ms
            )
        THEN
            RAISE EXCEPTION 'expired GitHub authority mint claim takeover is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_reclaim';
        END IF;
    ELSIF OLD.state = 'mint_retry_pending' AND NEW.state = 'claimed' THEN
        IF NEW.mint_attempt_count <> OLD.mint_attempt_count + 1
            OR NEW.mint_claim_fence <> OLD.mint_claim_fence + 1
            OR NEW.mint_claimed_at_ms < OLD.next_mint_at_ms
            OR NEW.last_mint_rejection_kind IS DISTINCT FROM OLD.last_mint_rejection_kind
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.mint_claimed_at_ms
            )
        THEN
            RAISE EXCEPTION 'definitive no-token GitHub mint retry claim is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_retry_claim';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'minting' THEN
        IF NEW.mint_attempt_count <> OLD.mint_attempt_count
            OR NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.mint_claimed_at_ms <> OLD.mint_claimed_at_ms
            OR NEW.mint_started_at_ms < OLD.mint_claimed_at_ms
            OR NEW.mint_started_at_ms >= OLD.mint_claim_expires_at_ms
            OR NEW.mint_started_at_ms::NUMERIC
                + NEW.mint_provider_request_millis::NUMERIC
                > OLD.mint_claim_expires_at_ms::NUMERIC
            OR NEW.mint_started_at_ms::NUMERIC
                + NEW.mint_provider_request_millis::NUMERIC
                > NEW.request_deadline_at_ms::NUMERIC
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.mint_started_at_ms
            )
        THEN
            RAISE EXCEPTION 'GitHub authority mint must begin under the exact live claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_begin';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'mint_retry_pending' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.next_mint_at_ms <= NEW.state_updated_at_ms
            OR NEW.next_mint_at_ms >= NEW.request_deadline_at_ms
            OR NEW.last_mint_rejection_kind IS NULL
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.state_updated_at_ms
            )
        THEN
            RAISE EXCEPTION 'GitHub no-token mint retry scheduling is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_retry_schedule';
        END IF;
    ELSIF OLD.state IN ('minting', 'mint_retry_pending') AND NEW.state = 'rejected' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.last_mint_rejection_kind IS NULL
            OR NEW.rejected_at_ms <> NEW.state_updated_at_ms
            OR NEW.terminal_reason NOT IN (
                'provider_mint_rejected', 'provider_mint_retry_expired'
            )
            OR (
                OLD.state = 'mint_retry_pending'
                AND NEW.terminal_reason <> 'provider_mint_retry_expired'
            )
        THEN
            RAISE EXCEPTION 'definitive GitHub mint rejection is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_rejection';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'indeterminate' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.indeterminate_at_ms < OLD.mint_started_at_ms
            OR NEW.indeterminate_at_ms >= OLD.conservative_expiry_at_ms
        THEN
            RAISE EXCEPTION 'ambiguous GitHub mint must retain its irreversible fence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_indeterminate';
        END IF;
    ELSIF OLD.state IN ('minting', 'indeterminate')
          AND NEW.state IN ('ready', 'revoke_pending') THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.safe_erase_after_ms IS NULL
            OR NEW.envelope_schema IS NULL
            OR NEW.state_updated_at_ms >= NEW.safe_erase_after_ms
            OR (
                NEW.state = 'ready' AND (
                    OLD.state <> 'minting'
                    OR NEW.commit_disposition <> 'deliverable'
                    OR NEW.provider_expires_at_ms IS NULL
                    OR NEW.provider_expires_at_ms::NUMERIC
                        <= NEW.state_updated_at_ms::NUMERIC + 60000
                    OR NOT automata_github_runtime_authority_is_current(
                        NEW, NEW.state_updated_at_ms
                    )
                )
            )
            OR (
                NEW.state = 'revoke_pending' AND (
                    NEW.ready_at_ms IS NOT NULL
                    OR NEW.revoke_pending_at_ms <> NEW.state_updated_at_ms
                    OR NEW.next_revoke_at_ms <> NEW.state_updated_at_ms
                )
            )
        THEN
            RAISE EXCEPTION 'minted GitHub authority finalization is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_finalize';
        END IF;
    ELSIF OLD.state = 'ready' AND NEW.state = 'revoke_pending' THEN
        IF NEW.revoke_pending_at_ms < OLD.ready_at_ms
            OR NEW.revoke_pending_at_ms >= OLD.safe_erase_after_ms
            OR NEW.revoke_pending_at_ms <> NEW.state_updated_at_ms
            OR NEW.next_revoke_at_ms <> NEW.state_updated_at_ms
        THEN
            RAISE EXCEPTION 'ready GitHub authority revocation transition is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revoke_pending';
        END IF;
    ELSIF OLD.state IN ('ready', 'revoke_pending') AND NEW.state = 'quarantined' THEN
        IF NEW.quarantine_at_ms <> NEW.state_updated_at_ms
            OR NEW.quarantine_kind IS NULL
            OR NEW.state_updated_at_ms >= NEW.safe_erase_after_ms
            OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
        THEN
            RAISE EXCEPTION 'GitHub authority quarantine observation is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_quarantine';
        END IF;
    ELSIF OLD.state = 'revoke_pending' AND NEW.state = 'revoke_pending' THEN
        IF OLD.revoke_claim_owner_id IS NULL
            AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF NEW.revoke_attempt_count <> OLD.revoke_attempt_count + 1
                OR NEW.revoke_claim_fence <> OLD.revoke_claim_fence + 1
                OR NEW.revoke_claimed_at_ms < OLD.next_revoke_at_ms
                OR NEW.revoke_claimed_at_ms <> NEW.state_updated_at_ms
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
                OR NEW.last_revoke_failure_kind
                    IS DISTINCT FROM OLD.last_revoke_failure_kind
            THEN
                RAISE EXCEPTION 'GitHub authority revoke claim is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_claim';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
            AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF NEW.revoke_attempt_count <> OLD.revoke_attempt_count + 1
                OR NEW.revoke_claim_fence <> OLD.revoke_claim_fence + 1
                OR NEW.revoke_claimed_at_ms < OLD.revoke_claim_expires_at_ms
                OR NEW.revoke_claimed_at_ms <> NEW.state_updated_at_ms
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
                OR NEW.last_revoke_failure_kind
                    IS DISTINCT FROM OLD.last_revoke_failure_kind
            THEN
                RAISE EXCEPTION 'expired GitHub authority revoke claim takeover is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_reclaim';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
            AND NEW.revoke_claim_owner_id IS NULL THEN
            IF NOT (
                NEW.revoke_attempt_count = OLD.revoke_attempt_count
                AND NEW.revoke_claim_fence = OLD.revoke_claim_fence
                AND NEW.last_revoke_failure_kind IS NOT NULL
                AND NEW.state_updated_at_ms >= OLD.revoke_claimed_at_ms
                AND (
                    (
                        NEW.state_updated_at_ms < OLD.revoke_claim_expires_at_ms
                        AND (
                            (
                                NEW.next_revoke_at_ms > NEW.state_updated_at_ms
                                AND NEW.next_revoke_at_ms < NEW.safe_erase_after_ms
                            ) OR NEW.next_revoke_at_ms = NEW.safe_erase_after_ms
                        )
                    ) OR (
                        NEW.state_updated_at_ms >= OLD.revoke_claim_expires_at_ms
                        AND NEW.state_updated_at_ms < NEW.safe_erase_after_ms
                        AND NEW.next_revoke_at_ms = NEW.safe_erase_after_ms
                        AND NEW.last_revoke_failure_kind = 'claim_budget_exhausted'
                        AND (
                            OLD.revoke_attempt_count = 64
                            OR OLD.revoke_claim_fence = 9223372036854775807
                        )
                    )
                )
            )
            THEN
                RAISE EXCEPTION 'GitHub authority revoke retry/defer is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_retry';
            END IF;
        ELSE
            RAISE EXCEPTION 'GitHub authority revoke self-transition is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revoke_self_transition';
        END IF;
    ELSIF OLD.state IN (
              'claimed', 'minting', 'indeterminate', 'ready',
              'revoke_pending', 'quarantined'
          ) AND NEW.state = 'revoked' THEN
        IF NEW.envelope_schema IS NOT NULL
            OR (
                NEW.terminal_reason = 'provider_revocation_confirmed' AND (
                    OLD.state <> 'revoke_pending'
                    OR OLD.revoke_claim_owner_id IS NULL
                    OR NEW.revoked_at_ms < OLD.revoke_claimed_at_ms
                    OR NEW.revoked_at_ms >= OLD.revoke_claim_expires_at_ms
                )
            )
            OR (
                NEW.terminal_reason = 'provider_authority_expired' AND NOT (
                    OLD.state IN ('ready', 'revoke_pending')
                    AND OLD.provider_expires_at_ms IS NOT NULL
                    AND NEW.revoked_at_ms >= OLD.safe_erase_after_ms
                    OR OLD.state IN ('minting', 'indeterminate')
                    AND NEW.provider_expires_at_ms IS NOT NULL
                    AND NEW.revoke_pending_at_ms = NEW.state_updated_at_ms
                    AND NEW.revoked_at_ms >= NEW.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'conservative_authority_expired' AND NOT (
                    OLD.state IN ('ready', 'revoke_pending')
                    AND OLD.provider_expires_at_ms IS NULL
                    AND NEW.revoked_at_ms >= OLD.safe_erase_after_ms
                    OR OLD.state IN ('minting', 'indeterminate')
                    AND NEW.provider_expires_at_ms IS NULL
                    AND NEW.revoke_pending_at_ms = NEW.state_updated_at_ms
                    AND NEW.revoked_at_ms >= NEW.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'quarantined_authority_expired' AND NOT (
                    OLD.state = 'quarantined'
                    AND NEW.revoked_at_ms >= OLD.safe_erase_after_ms
                    OR OLD.state IN ('ready', 'revoke_pending')
                    AND NEW.quarantine_at_ms = NEW.state_updated_at_ms
                    AND NEW.quarantine_kind IS NOT NULL
                    AND NEW.aad_digest IS NOT DISTINCT FROM OLD.aad_digest
                    AND NEW.revoked_at_ms >= OLD.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'indeterminate_authority_expired' AND (
                    OLD.state NOT IN ('minting', 'indeterminate')
                    OR NEW.revoked_at_ms < OLD.conservative_expiry_at_ms
                )
            )
            OR (
                NEW.terminal_reason = 'superseded_before_mint' AND (
                    OLD.state <> 'claimed'
                    OR automata_github_runtime_authority_is_current(
                        OLD, NEW.revoked_at_ms
                    )
                )
            )
            OR (
                NEW.terminal_reason = 'request_expired_before_mint' AND (
                    OLD.state <> 'claimed'
                    OR NEW.revoked_at_ms < OLD.request_deadline_at_ms
                )
            )
        THEN
            RAISE EXCEPTION 'GitHub authority terminal erasure is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_terminal_erasure';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub runtime authority lifecycle transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_lifecycle_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_02_v3_lifecycle_guard
BEFORE UPDATE ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION
    automata_enforce_github_runtime_authority_v3_lifecycle();

-- Every issued mint fence remains immutable evidence after terminal reduction
-- clears the mutable claim interval.
CREATE TABLE github_runtime_authority_mint_claims (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    claim_fence BIGINT NOT NULL,
    claim_owner_id UUID NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    CONSTRAINT github_runtime_authority_mint_claims_pk PRIMARY KEY (
        attempt_id, fencing_token, claim_fence
    ),
    CONSTRAINT github_runtime_authority_mint_claims_authority_fk FOREIGN KEY (
        attempt_id, fencing_token
    ) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token)
      ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_mint_claims_shape CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND fencing_token > 0
        AND claim_fence BETWEEN 1 AND 32
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND claimed_at_ms >= 0
        AND expires_at_ms > claimed_at_ms
    )
);

CREATE FUNCTION automata_guard_github_runtime_authority_mint_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'GitHub runtime-authority mint claims are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_claim_immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = NEW.attempt_id
          AND authority.fencing_token = NEW.fencing_token
          AND authority.tenant_id = NEW.tenant_id
          AND authority.state = 'claimed'
          AND authority.mint_claim_fence = NEW.claim_fence
          AND authority.mint_claim_owner_id = NEW.claim_owner_id
          AND authority.mint_claimed_at_ms = NEW.claimed_at_ms
          AND authority.mint_claim_expires_at_ms = NEW.expires_at_ms
        FOR KEY SHARE
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority mint claim is not exact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_claim_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_mint_claims_guard
BEFORE INSERT OR UPDATE OR DELETE ON github_runtime_authority_mint_claims
FOR EACH ROW EXECUTE FUNCTION
    automata_guard_github_runtime_authority_mint_claim();

-- The irreversible provider cutoff records the exact duration authorized by
-- PostgreSQL after KMS work.  This immutable evidence is the only accepted
-- acknowledgement-loss replay for an already-started mint fence.
CREATE TABLE github_runtime_authority_mint_begins (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    claim_fence BIGINT NOT NULL,
    claim_owner_id UUID NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    started_at_ms BIGINT NOT NULL,
    provider_request_millis BIGINT NOT NULL,
    CONSTRAINT github_runtime_authority_mint_begins_pk PRIMARY KEY (
        attempt_id, fencing_token, claim_fence
    ),
    CONSTRAINT github_runtime_authority_mint_begins_authority_fk FOREIGN KEY (
        attempt_id, fencing_token
    ) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token)
      ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_mint_begins_claim_fk FOREIGN KEY (
        attempt_id, fencing_token, claim_fence
    ) REFERENCES github_runtime_authority_mint_claims(
        attempt_id, fencing_token, claim_fence
    ) ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_mint_begins_shape CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND fencing_token > 0
        AND claim_fence BETWEEN 1 AND 32
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND claimed_at_ms >= 0
        AND expires_at_ms > claimed_at_ms
        AND started_at_ms BETWEEN claimed_at_ms AND expires_at_ms - 1
        AND provider_request_millis BETWEEN 1 AND 120000
        AND started_at_ms::NUMERIC + provider_request_millis::NUMERIC
            <= expires_at_ms::NUMERIC
    )
);

CREATE FUNCTION automata_guard_github_runtime_authority_mint_begin()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP <> 'INSERT' OR pg_trigger_depth() <> 2 THEN
        RAISE EXCEPTION 'GitHub runtime-authority mint begins are trigger-owned and immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_begin_immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        JOIN github_runtime_authority_mint_claims AS claim
          ON claim.attempt_id = authority.attempt_id
         AND claim.fencing_token = authority.fencing_token
         AND claim.claim_fence = authority.mint_claim_fence
         AND claim.tenant_id = authority.tenant_id
         AND claim.claim_owner_id = authority.mint_claim_owner_id
         AND claim.claimed_at_ms = NEW.claimed_at_ms
         AND claim.expires_at_ms = NEW.expires_at_ms
        WHERE authority.attempt_id = NEW.attempt_id
          AND authority.fencing_token = NEW.fencing_token
          AND authority.tenant_id = NEW.tenant_id
          AND authority.state = 'minting'
          AND authority.mint_claim_fence = NEW.claim_fence
          AND authority.mint_claim_owner_id = NEW.claim_owner_id
          AND authority.mint_claimed_at_ms = NEW.claimed_at_ms
          AND authority.mint_started_at_ms = NEW.started_at_ms
          AND authority.mint_provider_request_millis =
              NEW.provider_request_millis
          AND NEW.started_at_ms::NUMERIC +
              NEW.provider_request_millis::NUMERIC
              <= authority.request_deadline_at_ms::NUMERIC
        FOR KEY SHARE OF authority, claim
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority mint begin is not exact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_begin_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_mint_begins_guard
BEFORE INSERT OR UPDATE OR DELETE ON github_runtime_authority_mint_begins
FOR EACH ROW EXECUTE FUNCTION
    automata_guard_github_runtime_authority_mint_begin();

CREATE FUNCTION automata_capture_github_runtime_authority_mint_begin()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.state = 'claimed' AND NEW.state = 'minting' THEN
        INSERT INTO github_runtime_authority_mint_begins (
            tenant_id, attempt_id, fencing_token, claim_fence,
            claim_owner_id, claimed_at_ms, expires_at_ms,
            started_at_ms, provider_request_millis
        ) VALUES (
            NEW.tenant_id, NEW.attempt_id, NEW.fencing_token,
            NEW.mint_claim_fence, NEW.mint_claim_owner_id,
            NEW.mint_claimed_at_ms, OLD.mint_claim_expires_at_ms,
            NEW.mint_started_at_ms, NEW.mint_provider_request_millis
        );
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_03b_capture_mint_begin
AFTER UPDATE ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION
    automata_capture_github_runtime_authority_mint_begin();

-- Every issued revocation fence remains immutable evidence after the mutable
-- issuance row advances.  A late post-provider outcome can therefore prove
-- the exact owner/fence that was authorized even after claim expiry or a
-- subsequent takeover; no caller timestamp is authority for that proof.
CREATE TABLE github_runtime_authority_revocation_claims (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    claim_fence BIGINT NOT NULL,
    claim_owner_id UUID NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    aad_digest BYTEA NOT NULL,
    safe_erase_after_ms BIGINT NOT NULL,
    CONSTRAINT github_runtime_authority_revocation_claims_pk PRIMARY KEY (
        attempt_id, fencing_token, claim_fence
    ),
    CONSTRAINT github_runtime_authority_revocation_claims_authority_fk FOREIGN KEY (
        attempt_id, fencing_token
    ) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token)
      ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_revocation_claims_shape CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND fencing_token > 0
        AND claim_fence BETWEEN 1 AND 64
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND claimed_at_ms >= 0
        AND expires_at_ms > claimed_at_ms
        AND safe_erase_after_ms > expires_at_ms
        AND octet_length(aad_digest) = 32
    )
);

CREATE FUNCTION automata_guard_github_runtime_authority_revocation_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'GitHub runtime-authority revocation claims are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_revocation_claim_immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = NEW.attempt_id
          AND authority.fencing_token = NEW.fencing_token
          AND authority.tenant_id = NEW.tenant_id
          AND authority.state = 'revoke_pending'
          AND authority.revoke_claim_fence = NEW.claim_fence
          AND authority.revoke_claim_owner_id = NEW.claim_owner_id
          AND authority.revoke_claimed_at_ms = NEW.claimed_at_ms
          AND authority.revoke_claim_expires_at_ms = NEW.expires_at_ms
          AND authority.aad_digest = NEW.aad_digest
          AND authority.safe_erase_after_ms = NEW.safe_erase_after_ms
        FOR KEY SHARE
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority revocation claim is not exact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_revocation_claim_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_revocation_claims_guard
BEFORE INSERT OR UPDATE OR DELETE ON github_runtime_authority_revocation_claims
FOR EACH ROW EXECUTE FUNCTION
    automata_guard_github_runtime_authority_revocation_claim();

-- Capture every predecessor in the same statement that issues its mutable
-- fence.  Adapter-side verification remains defense in depth, but direct SQL
-- cannot create an otherwise-valid claim while omitting replay evidence.
CREATE FUNCTION automata_capture_github_runtime_authority_claim_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state = 'claimed'
        AND NEW.mint_claim_owner_id IS NOT NULL
        AND NEW.mint_claim_expires_at_ms IS NOT NULL
    THEN
        INSERT INTO github_runtime_authority_mint_claims (
            tenant_id, attempt_id, fencing_token, claim_fence,
            claim_owner_id, claimed_at_ms, expires_at_ms
        ) VALUES (
            NEW.tenant_id, NEW.attempt_id, NEW.fencing_token,
            NEW.mint_claim_fence, NEW.mint_claim_owner_id,
            NEW.mint_claimed_at_ms, NEW.mint_claim_expires_at_ms
        )
        ON CONFLICT (attempt_id, fencing_token, claim_fence) DO NOTHING;
    END IF;
    IF NEW.state = 'revoke_pending'
        AND NEW.revoke_claim_owner_id IS NOT NULL
        AND NEW.revoke_claimed_at_ms IS NOT NULL
        AND NEW.revoke_claim_expires_at_ms IS NOT NULL
    THEN
        INSERT INTO github_runtime_authority_revocation_claims (
            tenant_id, attempt_id, fencing_token, claim_fence,
            claim_owner_id, claimed_at_ms, expires_at_ms,
            aad_digest, safe_erase_after_ms
        ) VALUES (
            NEW.tenant_id, NEW.attempt_id, NEW.fencing_token,
            NEW.revoke_claim_fence, NEW.revoke_claim_owner_id,
            NEW.revoke_claimed_at_ms, NEW.revoke_claim_expires_at_ms,
            NEW.aad_digest, NEW.safe_erase_after_ms
        )
        ON CONFLICT (attempt_id, fencing_token, claim_fence) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_03_capture_claim_evidence
AFTER INSERT OR UPDATE ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION
    automata_capture_github_runtime_authority_claim_evidence();

CREATE FUNCTION automata_reject_github_runtime_authority_claim_evidence_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub runtime-authority claim evidence cannot be truncated'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_runtime_authority_claim_evidence_truncate';
END;
$automata$;

CREATE TRIGGER github_runtime_authority_mint_claims_reject_truncate
BEFORE TRUNCATE ON github_runtime_authority_mint_claims
FOR EACH STATEMENT EXECUTE FUNCTION
    automata_reject_github_runtime_authority_claim_evidence_truncate();

CREATE TRIGGER github_runtime_authority_mint_begins_reject_truncate
BEFORE TRUNCATE ON github_runtime_authority_mint_begins
FOR EACH STATEMENT EXECUTE FUNCTION
    automata_reject_github_runtime_authority_claim_evidence_truncate();

CREATE TRIGGER github_runtime_authority_revocation_claims_reject_truncate
BEFORE TRUNCATE ON github_runtime_authority_revocation_claims
FOR EACH STATEMENT EXECUTE FUNCTION
    automata_reject_github_runtime_authority_claim_evidence_truncate();

-- Operation digests are canonical SQL values, not opaque adapter labels.  The
-- transition trigger recomputes them from the exact immutable predecessor and
-- persisted request/result evidence.  Both applied transitions and terminal
-- observations require a reciprocal permanent receipt in the same commit.
CREATE FUNCTION automata_github_runtime_authority_hash_bytes(value BYTEA)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
AS $automata$
    SELECT pg_catalog.int8send(pg_catalog.octet_length(value)::BIGINT) || value
$automata$;

CREATE FUNCTION automata_github_runtime_authority_envelope_digest(
    envelope_schema INTEGER,
    wrapping_key_id TEXT,
    wrapped_data_key BYTEA,
    nonce BYTEA,
    ciphertext BYTEA
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
AS $automata$
    SELECT pg_catalog.sha256(
        pg_catalog.convert_to(
            'automata.store.github-runtime-authority-envelope.v1', 'UTF8'
        ) || pg_catalog.decode('00', 'hex')
        || pg_catalog.int2send(envelope_schema::SMALLINT)
        || automata_github_runtime_authority_hash_bytes(
            pg_catalog.convert_to(wrapping_key_id, 'UTF8')
        )
        || automata_github_runtime_authority_hash_bytes(wrapped_data_key)
        || automata_github_runtime_authority_hash_bytes(nonce)
        || automata_github_runtime_authority_hash_bytes(ciphertext)
    )
$automata$;

CREATE FUNCTION automata_github_runtime_authority_operation_digest(
    request_kind TEXT,
    attempt_id UUID,
    fencing_token BIGINT,
    claim_fence BIGINT,
    claim_owner_id UUID,
    claim_claimed_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    observed_at_ms BIGINT,
    retry_at_ms BIGINT,
    failure_kind TEXT,
    commit_disposition TEXT,
    provider_expires_at_ms BIGINT,
    safe_erase_after_ms BIGINT,
    plaintext_schema INTEGER,
    plaintext_size_bytes BIGINT,
    plaintext_digest BYTEA,
    aad_digest BYTEA,
    envelope_digest BYTEA
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
AS $automata$
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
$automata$;

CREATE TABLE github_runtime_authority_operation_transitions (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    operation_kind TEXT COLLATE "C" NOT NULL,
    claim_fence BIGINT NOT NULL,
    claim_owner_id UUID,
    claim_claimed_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    disposition TEXT COLLATE "C" NOT NULL,
    request_kind TEXT COLLATE "C" NOT NULL,
    request_observed_at_ms BIGINT NOT NULL,
    request_retry_at_ms BIGINT,
    request_failure_kind TEXT COLLATE "C",
    request_commit_disposition TEXT COLLATE "C",
    request_provider_expires_at_ms BIGINT,
    request_safe_erase_after_ms BIGINT,
    request_plaintext_schema INTEGER,
    request_plaintext_size_bytes BIGINT,
    request_plaintext_digest BYTEA,
    request_aad_digest BYTEA,
    request_envelope_digest BYTEA,
    operation_digest BYTEA NOT NULL,
    predecessor_state TEXT COLLATE "C" NOT NULL,
    predecessor_updated_at_ms BIGINT NOT NULL,
    result_state TEXT COLLATE "C" NOT NULL,
    result_updated_at_ms BIGINT NOT NULL,
    result_terminal_reason TEXT COLLATE "C",
    CONSTRAINT github_runtime_authority_operation_transitions_pk PRIMARY KEY (
        attempt_id, fencing_token, operation_kind, claim_fence
    ),
    CONSTRAINT github_runtime_authority_operation_transitions_authority_fk
      FOREIGN KEY (attempt_id, fencing_token)
      REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token)
      ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_operation_transitions_shape CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND fencing_token > 0
        AND octet_length(operation_digest) = 32
        AND disposition IN ('applied', 'terminal_erasable')
        AND predecessor_updated_at_ms >= 0
        AND result_updated_at_ms >= predecessor_updated_at_ms
        AND (
            operation_kind = 'mint_commit'
            AND request_kind = 'mint_commit'
            AND claim_fence BETWEEN 1 AND 32
            AND claim_owner_id IS NOT NULL
            AND claim_claimed_at_ms >= 0
            AND claim_expires_at_ms > claim_claimed_at_ms
            OR operation_kind = 'quarantine'
            AND request_kind = 'quarantine'
            AND claim_fence = 0
            AND claim_owner_id IS NULL
            AND claim_claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            OR operation_kind = 'revocation_outcome'
            AND request_kind IN (
                'revocation_retry', 'revocation_defer', 'revocation_confirm'
            )
            AND claim_fence BETWEEN 1 AND 64
            AND claim_owner_id IS NOT NULL
            AND claim_claimed_at_ms >= 0
            AND claim_expires_at_ms > claim_claimed_at_ms
        )
        AND (
            disposition = 'applied'
            AND (
                operation_kind = 'mint_commit'
                AND predecessor_state IN ('minting', 'indeterminate')
                AND result_state IN ('ready', 'revoke_pending', 'revoked')
                OR operation_kind = 'quarantine'
                AND predecessor_state IN ('ready', 'revoke_pending')
                AND result_state IN ('quarantined', 'revoked')
                OR operation_kind = 'revocation_outcome'
                AND predecessor_state = 'revoke_pending'
                AND result_state IN ('revoke_pending', 'revoked')
            )
            OR disposition = 'terminal_erasable'
            AND predecessor_state = result_state
            AND predecessor_updated_at_ms = result_updated_at_ms
            AND (
                operation_kind = 'mint_commit'
                AND result_state = 'revoked'
                AND result_terminal_reason = 'indeterminate_authority_expired'
                OR operation_kind = 'quarantine'
                AND result_state = 'revoked'
                AND result_terminal_reason IS NOT NULL
                OR operation_kind = 'revocation_outcome'
                AND result_state IN ('revoke_pending', 'quarantined', 'revoked')
            )
        )
    )
);

CREATE FUNCTION automata_guard_github_runtime_authority_operation_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP <> 'INSERT' OR pg_trigger_depth() <> 2 THEN
        RAISE EXCEPTION 'GitHub runtime-authority operation transitions are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_operation_transition_immutable';
    END IF;
    NEW.operation_digest := automata_github_runtime_authority_operation_digest(
        NEW.request_kind, NEW.attempt_id, NEW.fencing_token,
        NEW.claim_fence, NEW.claim_owner_id, NEW.claim_claimed_at_ms,
        NEW.claim_expires_at_ms, NEW.request_observed_at_ms,
        NEW.request_retry_at_ms, NEW.request_failure_kind,
        NEW.request_commit_disposition, NEW.request_provider_expires_at_ms,
        NEW.request_safe_erase_after_ms, NEW.request_plaintext_schema,
        NEW.request_plaintext_size_bytes, NEW.request_plaintext_digest,
        NEW.request_aad_digest, NEW.request_envelope_digest
    );
    IF NEW.operation_digest IS NULL THEN
        RAISE EXCEPTION 'GitHub runtime-authority operation digest is not canonical'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_operation_digest_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_operation_transitions_guard
BEFORE INSERT OR UPDATE OR DELETE
ON github_runtime_authority_operation_transitions
FOR EACH ROW EXECUTE FUNCTION
    automata_guard_github_runtime_authority_operation_transition();

CREATE FUNCTION automata_capture_github_runtime_authority_operation_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    predecessor_claimed_at BIGINT;
    predecessor_expires_at BIGINT;
    operation_kind TEXT;
    receipt_disposition TEXT;
BEGIN
    IF OLD.state IN ('minting', 'indeterminate')
        AND NEW.state IN ('ready', 'revoke_pending', 'revoked')
        AND OLD.safe_erase_after_ms IS NULL
        AND NEW.safe_erase_after_ms IS NOT NULL
    THEN
        operation_kind := 'mint_commit';
        receipt_disposition := 'applied';
        SELECT claim.claimed_at_ms, claim.expires_at_ms
          INTO STRICT predecessor_claimed_at, predecessor_expires_at
        FROM github_runtime_authority_mint_claims AS claim
        WHERE claim.attempt_id = OLD.attempt_id
          AND claim.fencing_token = OLD.fencing_token
          AND claim.claim_fence = OLD.mint_claim_fence
          AND claim.tenant_id = OLD.tenant_id
          AND claim.claim_owner_id = OLD.mint_claim_owner_id
          AND claim.claimed_at_ms = OLD.mint_claimed_at_ms
        FOR KEY SHARE;
        IF NEW.operation_request_kind <> 'mint_commit'
            OR NEW.operation_request_claim_fence <> OLD.mint_claim_fence
            OR NEW.operation_request_claim_owner_id IS DISTINCT FROM
                OLD.mint_claim_owner_id
            OR NEW.operation_request_commit_disposition IS DISTINCT FROM
                NEW.commit_disposition
            OR NEW.operation_request_provider_expires_at_ms IS DISTINCT FROM
                NEW.provider_expires_at_ms
            OR NEW.operation_request_safe_erase_after_ms IS DISTINCT FROM
                NEW.safe_erase_after_ms
            OR NEW.operation_request_plaintext_schema IS DISTINCT FROM
                NEW.plaintext_schema
            OR NEW.operation_request_plaintext_size_bytes IS DISTINCT FROM
                NEW.plaintext_size_bytes
            OR NEW.operation_request_plaintext_digest IS DISTINCT FROM
                NEW.plaintext_digest
            OR NEW.operation_request_aad_digest IS DISTINCT FROM NEW.aad_digest
            OR NEW.operation_request_observed_at_ms < predecessor_claimed_at
            OR NEW.operation_request_observed_at_ms >=
                NEW.conservative_expiry_at_ms
            OR NEW.envelope_schema IS NOT NULL AND
                NEW.operation_request_envelope_digest IS DISTINCT FROM
                    automata_github_runtime_authority_envelope_digest(
                        NEW.envelope_schema, NEW.wrapping_key_id,
                        NEW.wrapped_data_key, NEW.nonce, NEW.ciphertext
                    )
        THEN
            RAISE EXCEPTION 'GitHub mint transition request evidence is not exact'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_transition_exact';
        END IF;
    ELSIF OLD.state IN ('ready', 'revoke_pending')
        AND NEW.state IN ('quarantined', 'revoked')
        AND NEW.quarantine_at_ms IS DISTINCT FROM OLD.quarantine_at_ms
    THEN
        operation_kind := 'quarantine';
        receipt_disposition := 'applied';
        IF NEW.operation_request_kind <> 'quarantine'
            OR NEW.operation_request_claim_fence <> 0
            OR NEW.operation_request_claim_owner_id IS NOT NULL
            OR NEW.operation_request_failure_kind IS DISTINCT FROM
                NEW.quarantine_kind
            OR NEW.operation_request_aad_digest IS DISTINCT FROM OLD.aad_digest
            OR NEW.operation_request_observed_at_ms < NEW.requested_at_ms
            OR NEW.operation_request_observed_at_ms >= OLD.safe_erase_after_ms
        THEN
            RAISE EXCEPTION 'GitHub quarantine transition request evidence is not exact'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_quarantine_transition_exact';
        END IF;
    ELSIF OLD.state = 'revoke_pending'
        AND OLD.revoke_claim_owner_id IS NOT NULL
        AND (
            NEW.state = 'revoked'
            AND NEW.terminal_reason = 'provider_revocation_confirmed'
            OR NEW.state = 'revoke_pending'
            AND NEW.revoke_claim_owner_id IS NULL
            AND NEW.last_revoke_failure_kind <> 'claim_budget_exhausted'
        )
    THEN
        operation_kind := 'revocation_outcome';
        receipt_disposition := 'applied';
        predecessor_claimed_at := OLD.revoke_claimed_at_ms;
        predecessor_expires_at := OLD.revoke_claim_expires_at_ms;
        IF NEW.operation_request_kind NOT IN (
                'revocation_retry', 'revocation_defer', 'revocation_confirm'
            )
            OR NEW.operation_request_claim_fence <> OLD.revoke_claim_fence
            OR NEW.operation_request_claim_owner_id IS DISTINCT FROM
                OLD.revoke_claim_owner_id
            OR NEW.operation_request_observed_at_ms < predecessor_claimed_at
            OR NEW.operation_request_observed_at_ms >= predecessor_expires_at
            OR NEW.operation_request_kind = 'revocation_retry' AND (
                NEW.last_revoke_failure_kind IS DISTINCT FROM
                    NEW.operation_request_failure_kind
                OR NEW.next_revoke_at_ms::NUMERIC <> LEAST(
                    NEW.safe_erase_after_ms::NUMERIC,
                    NEW.state_updated_at_ms::NUMERIC
                        + NEW.operation_request_retry_at_ms::NUMERIC
                        - NEW.operation_request_observed_at_ms::NUMERIC
                )
                OR NEW.operation_request_retry_at_ms >=
                    NEW.safe_erase_after_ms
            )
            OR NEW.operation_request_kind = 'revocation_defer' AND
                NEW.last_revoke_failure_kind IS DISTINCT FROM
                    NEW.operation_request_failure_kind
            OR NEW.operation_request_kind = 'revocation_confirm' AND NOT (
                NEW.state = 'revoked'
                AND NEW.terminal_reason = 'provider_revocation_confirmed'
            )
        THEN
            RAISE EXCEPTION 'GitHub revocation transition request evidence is not exact'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revocation_transition_exact';
        END IF;
    ELSIF OLD.state = NEW.state
        AND NEW.operation_request_kind IS NOT NULL
        AND automata_github_runtime_authority_same_non_operation_state(
            OLD, NEW
        )
    THEN
        receipt_disposition := 'terminal_erasable';
        IF NEW.operation_request_kind = 'mint_commit' THEN
            operation_kind := 'mint_commit';
            SELECT claim.claimed_at_ms, claim.expires_at_ms
              INTO STRICT predecessor_claimed_at, predecessor_expires_at
            FROM github_runtime_authority_mint_claims AS claim
            WHERE claim.attempt_id = NEW.attempt_id
              AND claim.fencing_token = NEW.fencing_token
              AND claim.claim_fence = NEW.operation_request_claim_fence
              AND claim.tenant_id = NEW.tenant_id
              AND claim.claim_owner_id = NEW.operation_request_claim_owner_id
            FOR KEY SHARE;
            IF NEW.state <> 'revoked'
                OR NEW.terminal_reason <> 'indeterminate_authority_expired'
                OR NEW.envelope_schema IS NOT NULL
                OR database_now < NEW.conservative_expiry_at_ms
                OR NEW.mint_started_at_ms IS NULL
                OR NEW.operation_request_observed_at_ms <
                    predecessor_claimed_at
                OR NEW.operation_request_observed_at_ms >=
                    NEW.conservative_expiry_at_ms
            THEN
                RAISE EXCEPTION 'GitHub mint terminal observation is not erasable'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_mint_terminal_exact';
            END IF;
        ELSIF NEW.operation_request_kind = 'quarantine' THEN
            operation_kind := 'quarantine';
            IF NEW.operation_request_claim_fence <> 0
                OR NEW.operation_request_claim_owner_id IS NOT NULL
                OR NEW.state <> 'revoked'
                OR NEW.envelope_schema IS NOT NULL
                OR NEW.safe_erase_after_ms IS NULL
                OR database_now < NEW.safe_erase_after_ms
                OR NEW.operation_request_aad_digest IS DISTINCT FROM NEW.aad_digest
                OR NEW.operation_request_observed_at_ms < NEW.requested_at_ms
                OR NEW.operation_request_observed_at_ms >=
                    NEW.safe_erase_after_ms
            THEN
                RAISE EXCEPTION 'GitHub quarantine terminal observation is not erasable'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_quarantine_terminal_exact';
            END IF;
        ELSIF NEW.operation_request_kind IN (
            'revocation_retry', 'revocation_defer', 'revocation_confirm'
        ) THEN
            operation_kind := 'revocation_outcome';
            SELECT claim.claimed_at_ms, claim.expires_at_ms
              INTO STRICT predecessor_claimed_at, predecessor_expires_at
            FROM github_runtime_authority_revocation_claims AS claim
            WHERE claim.attempt_id = NEW.attempt_id
              AND claim.fencing_token = NEW.fencing_token
              AND claim.claim_fence = NEW.operation_request_claim_fence
              AND claim.tenant_id = NEW.tenant_id
              AND claim.claim_owner_id = NEW.operation_request_claim_owner_id
              AND claim.aad_digest = NEW.aad_digest
              AND claim.safe_erase_after_ms = NEW.safe_erase_after_ms
            FOR KEY SHARE;
            IF NOT (
                NEW.state IN ('quarantined', 'revoked')
                OR NEW.revoke_claim_fence <>
                    NEW.operation_request_claim_fence
                OR database_now >= predecessor_expires_at
            )
                OR NEW.operation_request_observed_at_ms < predecessor_claimed_at
                OR NEW.operation_request_observed_at_ms >= predecessor_expires_at
                OR NEW.operation_request_kind = 'revocation_retry'
                AND NEW.operation_request_retry_at_ms >=
                    NEW.safe_erase_after_ms
            THEN
                RAISE EXCEPTION 'GitHub revocation terminal observation is not erasable'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revocation_terminal_exact';
            END IF;
        ELSE
            RETURN NEW;
        END IF;
    ELSE
        RETURN NEW;
    END IF;

    INSERT INTO github_runtime_authority_operation_transitions (
        tenant_id, attempt_id, fencing_token, operation_kind, claim_fence,
        claim_owner_id, claim_claimed_at_ms, claim_expires_at_ms,
        disposition, request_kind, request_observed_at_ms,
        request_retry_at_ms, request_failure_kind,
        request_commit_disposition, request_provider_expires_at_ms,
        request_safe_erase_after_ms, request_plaintext_schema,
        request_plaintext_size_bytes, request_plaintext_digest,
        request_aad_digest, request_envelope_digest,
        predecessor_state, predecessor_updated_at_ms,
        result_state, result_updated_at_ms, result_terminal_reason
    ) VALUES (
        NEW.tenant_id, NEW.attempt_id, NEW.fencing_token, operation_kind,
        COALESCE(NEW.operation_request_claim_fence, 0),
        NEW.operation_request_claim_owner_id, predecessor_claimed_at,
        predecessor_expires_at, receipt_disposition,
        NEW.operation_request_kind, NEW.operation_request_observed_at_ms,
        NEW.operation_request_retry_at_ms, NEW.operation_request_failure_kind,
        NEW.operation_request_commit_disposition,
        NEW.operation_request_provider_expires_at_ms,
        NEW.operation_request_safe_erase_after_ms,
        NEW.operation_request_plaintext_schema,
        NEW.operation_request_plaintext_size_bytes,
        NEW.operation_request_plaintext_digest,
        NEW.operation_request_aad_digest,
        NEW.operation_request_envelope_digest,
        OLD.state, OLD.state_updated_at_ms,
        NEW.state, NEW.state_updated_at_ms, NEW.terminal_reason
    );
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_04_capture_operation_transition
AFTER UPDATE ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION
    automata_capture_github_runtime_authority_operation_transition();

-- Permanent operation evidence is bounded by the closed fence ceilings and
-- has no time-, label-, or compaction-based deletion path.
CREATE TABLE github_runtime_authority_operation_receipts (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    operation_kind TEXT COLLATE "C" NOT NULL,
    claim_fence BIGINT NOT NULL,
    operation_digest BYTEA NOT NULL,
    disposition TEXT COLLATE "C" NOT NULL,
    claim_owner_id UUID,
    claim_claimed_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    result_state TEXT COLLATE "C" NOT NULL,
    result_updated_at_ms BIGINT NOT NULL,
    result_terminal_reason TEXT COLLATE "C",
    applied_at_ms BIGINT NOT NULL,
    CONSTRAINT github_runtime_authority_operation_receipts_pk PRIMARY KEY (
        attempt_id, fencing_token, operation_kind, claim_fence
    ),
    CONSTRAINT github_runtime_authority_operation_receipts_authority_fk FOREIGN KEY (
        attempt_id, fencing_token
    ) REFERENCES github_runtime_authority_issuances(attempt_id, fencing_token)
      ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_operation_receipts_shape CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND fencing_token > 0
        AND octet_length(operation_digest) = 32
        AND disposition IN ('applied', 'terminal_erasable')
        AND result_updated_at_ms >= 0
        AND applied_at_ms >= 0
        AND operation_kind IN (
            'mint_commit', 'quarantine', 'revocation_outcome'
        )
        AND (
            operation_kind = 'quarantine'
            AND claim_fence = 0
            AND claim_owner_id IS NULL
            AND claim_claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            OR operation_kind <> 'quarantine'
            AND claim_fence > 0
            AND claim_owner_id IS NOT NULL
            AND claim_claimed_at_ms >= 0
            AND claim_expires_at_ms > claim_claimed_at_ms
        )
    )
);

CREATE FUNCTION automata_validate_github_runtime_authority_operation_receipt()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_operation_transitions AS transition
        WHERE transition.attempt_id = NEW.attempt_id
          AND transition.fencing_token = NEW.fencing_token
          AND transition.tenant_id = NEW.tenant_id
          AND transition.operation_kind = NEW.operation_kind
          AND transition.claim_fence = NEW.claim_fence
          AND transition.operation_digest = NEW.operation_digest
          AND transition.disposition = NEW.disposition
          AND transition.claim_owner_id IS NOT DISTINCT FROM NEW.claim_owner_id
          AND transition.claim_claimed_at_ms
              IS NOT DISTINCT FROM NEW.claim_claimed_at_ms
          AND transition.claim_expires_at_ms
              IS NOT DISTINCT FROM NEW.claim_expires_at_ms
          AND transition.result_state = NEW.result_state
          AND transition.result_updated_at_ms = NEW.result_updated_at_ms
          AND transition.result_terminal_reason
              IS NOT DISTINCT FROM NEW.result_terminal_reason
        FOR KEY SHARE
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority receipt lacks its canonical transition'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_operation_receipt_transition_exact';
    END IF;
    NEW.applied_at_ms := database_now;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_operation_receipts_00_validate
BEFORE INSERT ON github_runtime_authority_operation_receipts
FOR EACH ROW EXECUTE FUNCTION
    automata_validate_github_runtime_authority_operation_receipt();

CREATE FUNCTION automata_guard_github_runtime_authority_operation_receipt()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub runtime-authority operation evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_runtime_authority_operation_receipt_immutable';
END;
$automata$;

CREATE TRIGGER github_runtime_authority_operation_receipts_guard
BEFORE UPDATE OR DELETE ON github_runtime_authority_operation_receipts
FOR EACH ROW EXECUTE FUNCTION
    automata_guard_github_runtime_authority_operation_receipt();

CREATE FUNCTION automata_require_github_runtime_authority_operation_receipt()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_operation_receipts AS receipt
        WHERE receipt.attempt_id = NEW.attempt_id
          AND receipt.fencing_token = NEW.fencing_token
          AND receipt.tenant_id = NEW.tenant_id
          AND receipt.operation_kind = NEW.operation_kind
          AND receipt.claim_fence = NEW.claim_fence
          AND receipt.operation_digest = NEW.operation_digest
          AND receipt.disposition = NEW.disposition
          AND receipt.claim_owner_id IS NOT DISTINCT FROM NEW.claim_owner_id
          AND receipt.claim_claimed_at_ms
              IS NOT DISTINCT FROM NEW.claim_claimed_at_ms
          AND receipt.claim_expires_at_ms
              IS NOT DISTINCT FROM NEW.claim_expires_at_ms
          AND receipt.result_state = NEW.result_state
          AND receipt.result_updated_at_ms = NEW.result_updated_at_ms
          AND receipt.result_terminal_reason
              IS NOT DISTINCT FROM NEW.result_terminal_reason
        FOR KEY SHARE
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority transition lacks its exact receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_operation_transition_receipt_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER github_runtime_authority_operation_transition_receipt
AFTER INSERT ON github_runtime_authority_operation_transitions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
    automata_require_github_runtime_authority_operation_receipt();

CREATE FUNCTION automata_reject_github_runtime_authority_operation_receipt_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub runtime-authority operation receipts cannot be truncated'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_runtime_authority_operation_receipt_truncate';
END;
$automata$;

CREATE TRIGGER github_runtime_authority_operation_receipts_reject_truncate
BEFORE TRUNCATE ON github_runtime_authority_operation_receipts
FOR EACH STATEMENT EXECUTE FUNCTION
    automata_reject_github_runtime_authority_operation_receipt_truncate();

CREATE TRIGGER github_runtime_authority_operation_transitions_reject_truncate
BEFORE TRUNCATE ON github_runtime_authority_operation_transitions
FOR EACH STATEMENT EXECUTE FUNCTION
    automata_reject_github_runtime_authority_operation_receipt_truncate();
