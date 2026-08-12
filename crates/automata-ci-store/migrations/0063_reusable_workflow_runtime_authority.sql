-- Extend runtime authority and queue-reconciliation evidence to sealed reusable
-- workflow children. Root invocations retain their existing authority path;
-- children gain no authority until the exact digest-bound publication is sealed.

-- OIDC is a permission-bearing capability. A reusable child must therefore
-- have id-token: write in the immutable permission snapshot whose digest is
-- bound by both planning and publication. Roots keep their historical policy.
CREATE FUNCTION automata_reusable_workflow_oidc_permission_authorized(
    target_run_id UUID,
    target_invocation_id UUID
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        WHERE marker.run_id = target_run_id
          AND (
              marker.root_invocation_id = target_invocation_id
              OR (
                  automata_workflow_plan_v2_invocation_published(
                      target_run_id, target_invocation_id
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM workflow_plan_v2_reusable_invocation_expansions AS planned
                      JOIN workflow_plan_v2_reusable_call_publications AS publication
                        ON publication.run_id = planned.run_id
                       AND publication.child_invocation_id = planned.invocation_id
                       AND publication.parent_invocation_id = planned.parent_invocation_id
                       AND publication.caller_logical_job_id =
                           planned.caller_logical_job_id
                       AND publication.permission_digest = planned.permission_digest
                       AND publication.condition_matched
                       AND publication.child_graph_sealed_at_ms =
                           publication.published_at_ms
                      JOIN workflow_plan_v2_reusable_permission_snapshots AS permission_snapshot
                        ON permission_snapshot.run_id = planned.run_id
                       AND permission_snapshot.invocation_id = planned.invocation_id
                       AND permission_snapshot.permission_digest = planned.permission_digest
                      LEFT JOIN workflow_plan_v2_reusable_permission_grants AS id_token_grant
                        ON id_token_grant.run_id = permission_snapshot.run_id
                       AND id_token_grant.invocation_id =
                           permission_snapshot.invocation_id
                       AND id_token_grant.permission_name = 'id-token'
                      WHERE planned.run_id = target_run_id
                        AND planned.invocation_id = target_invocation_id
                        AND planned.depth > 0
                        AND COALESCE(
                            id_token_grant.permission_level,
                            permission_snapshot.default_level
                        ) = 'write'
                  )
              )
          )
    )
$automata$;

-- Preparation claims must bind the exact context selected for their
-- invocation. Roots retain the admission context; children use only the
-- sealed call publication context and can never fall back to the root.
CREATE OR REPLACE FUNCTION automata_validate_logical_preparation_base_context()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        WHERE marker.run_id = NEW.run_id
          AND (
              (
                  marker.root_invocation_id = NEW.invocation_id
                  AND (
                      (
                          NEW.base_context_kind = 'root_empty'
                          AND marker.base_context_digest IS NULL
                          AND marker.base_context_object_key IS NULL
                          AND marker.base_context_size_bytes IS NULL
                          AND marker.base_context_media_type IS NULL
                          AND marker.base_context_schema IS NULL
                      ) OR (
                          NEW.base_context_kind = 'admission_v2'
                          AND marker.base_context_digest = NEW.base_context_digest
                          AND marker.base_context_object_key =
                              NEW.base_context_object_key
                          AND marker.base_context_size_bytes =
                              NEW.base_context_size_bytes
                          AND marker.base_context_media_type =
                              NEW.base_context_media_type
                          AND marker.base_context_schema = NEW.base_context_schema
                          AND marker.base_context_schema = 2
                      )
                  )
              ) OR (
                  marker.root_invocation_id <> NEW.invocation_id
                  AND NEW.base_context_kind = 'admission_v2'
                  AND automata_workflow_plan_v2_invocation_published(
                      NEW.run_id, NEW.invocation_id
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM workflow_plan_v2_reusable_call_publications AS publication
                      WHERE publication.run_id = NEW.run_id
                        AND publication.child_invocation_id = NEW.invocation_id
                        AND publication.condition_matched
                        AND publication.child_graph_sealed_at_ms =
                            publication.published_at_ms
                        AND publication.runtime_context_digest =
                            NEW.base_context_digest
                        AND publication.runtime_context_object_key =
                            NEW.base_context_object_key
                        AND publication.runtime_context_size_bytes =
                            NEW.base_context_size_bytes
                        AND publication.runtime_context_media_type =
                            NEW.base_context_media_type
                        AND publication.runtime_context_schema =
                            NEW.base_context_schema
                        AND publication.runtime_context_schema = 2
                  )
              )
          )
    ) THEN
        RAISE EXCEPTION 'logical preparation base context disagrees with admission'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_activation_preparation_base_context_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

-- An idle receipt is valid only when no runnable published invocation exists.
-- This is the same predicate used by the production selectors, so a sealed
-- child cannot be hidden by recording an idle reconciliation outcome.
CREATE OR REPLACE FUNCTION automata_validate_activation_work_selection_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT;
    replay_floor BIGINT;
    exact_evidence BOOLEAN := FALSE;
    ready_exists BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.outcome <> 'selecting' THEN
            RAISE EXCEPTION 'activation selection must begin as a provisional reservation'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_selection_reservation_first';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.outcome <> 'selecting'
        OR NEW.selection_id IS DISTINCT FROM OLD.selection_id
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.requested_at_ms IS DISTINCT FROM OLD.requested_at_ms
        OR NEW.duration_ms IS DISTINCT FROM OLD.duration_ms
        OR NEW.outcome = 'selecting'
    THEN
        RAISE EXCEPTION 'activation selection transition is immutable or invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_transition';
    END IF;
    SELECT replay_floor_ms INTO replay_floor
    FROM workflow_plan_v2_work_selection_replay_horizons
    WHERE queue_name = 'activation'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'activation selection replay authority is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_horizon_required';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NEW.requested_at_ms <= replay_floor
        OR NEW.requested_at_ms < database_now - 60000
        OR NEW.requested_at_ms > database_now + 60000
    THEN
        RAISE EXCEPTION 'activation selection request is outside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_request_time';
    END IF;
    IF NEW.claimed_at_ms > database_now
        OR database_now - NEW.claimed_at_ms > 60000
        OR (NEW.outcome <> 'quarantined' AND (
            NEW.expires_at_ms <= database_now
            OR NEW.expires_at_ms - database_now < 1000
        ))
    THEN
        RAISE EXCEPTION 'activation selection issue time is not database-current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_database_time';
    END IF;

    IF NEW.outcome = 'claimed' AND NEW.authority_kind = 'preparation' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_preparation_claims AS claim
            JOIN workflow_plan_v2_jobs AS job ON job.id = claim.logical_job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE claim.logical_job_id = NEW.logical_job_id
              AND repository.tenant_id = NEW.tenant_id
              AND job.run_id = NEW.run_id
              AND job.invocation_id = NEW.invocation_id
              AND claim.origin_selection_id = NEW.selection_id
              AND claim.owner_id = NEW.owner_id
              AND claim.generation = NEW.generation
              AND claim.descriptor_digest = NEW.authority_digest
              AND claim.claimed_at_ms = NEW.claimed_at_ms
              AND claim.expires_at_ms = NEW.expires_at_ms
              AND claim.state = 'preparing'
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'claimed' AND NEW.authority_kind = 'activation' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_jobs AS job
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE job.id = NEW.logical_job_id
              AND repository.tenant_id = NEW.tenant_id
              AND job.run_id = NEW.run_id
              AND job.invocation_id = NEW.invocation_id
              AND job.activation_origin_selection_id = NEW.selection_id
              AND job.activation_owner_id = NEW.owner_id
              AND job.activation_fence = NEW.generation
              AND job.activation_input_digest = NEW.authority_digest
              AND job.activation_claimed_at_ms = NEW.claimed_at_ms
              AND job.activation_expires_at_ms = NEW.expires_at_ms
              AND job.state = 'activating'
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_work_quarantines AS quarantine
            WHERE quarantine.logical_job_id = NEW.logical_job_id
              AND quarantine.tenant_id = NEW.tenant_id
              AND quarantine.run_id = NEW.run_id
              AND quarantine.invocation_id = NEW.invocation_id
              AND quarantine.selection_id = NEW.selection_id
              AND quarantine.selection_owner_id = NEW.owner_id
              AND quarantine.selection_requested_at_ms = NEW.requested_at_ms
              AND quarantine.selection_duration_ms = NEW.duration_ms
              AND quarantine.selection_generation = NEW.generation
              AND quarantine.selection_claimed_at_ms = NEW.claimed_at_ms
              AND quarantine.selection_expires_at_ms = NEW.expires_at_ms
              AND quarantine.authority_kind = NEW.authority_kind
              AND quarantine.authority_digest = NEW.authority_digest
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'contended' THEN
        exact_evidence := TRUE;
    ELSE
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_jobs AS job
            JOIN workflow_plan_v2_invocations AS invocation
              ON invocation.run_id = job.run_id
             AND invocation.id = job.invocation_id
            JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            LEFT JOIN workflow_plan_v2_activation_preparation_claims AS preparation
              ON preparation.logical_job_id = job.id
            LEFT JOIN workflow_plan_v2_activation_work_quarantines AS quarantine
              ON quarantine.logical_job_id = job.id
            WHERE job.execution_kind = 'steps'
              AND automata_workflow_plan_v2_invocation_published(
                  marker.run_id, invocation.id
              )
              AND invocation.state IN ('pending', 'active')
              AND marker.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress')
              AND quarantine.logical_job_id IS NULL
              AND ((job.state = 'pending' AND (
                  preparation.logical_job_id IS NULL OR preparation.state = 'prepared'
                  OR (preparation.state = 'preparing'
                      AND preparation.expires_at_ms <= NEW.claimed_at_ms)
              )) OR (job.state = 'activating'
                     AND job.activation_expires_at_ms <= NEW.claimed_at_ms))
              AND NOT EXISTS (
                  SELECT 1
                  FROM workflow_plan_v2_dependencies AS dependency
                  LEFT JOIN workflow_plan_v2_job_result_claims AS result_claim
                    ON result_claim.logical_job_id = dependency.prerequisite_job_id
                   AND result_claim.state = 'finalized'
                  WHERE dependency.run_id = job.run_id
                    AND dependency.invocation_id = job.invocation_id
                    AND dependency.logical_job_id = job.id
                    AND result_claim.logical_job_id IS NULL
              )
        ) INTO ready_exists;
        exact_evidence := NOT ready_exists;
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'activation selection lacks exact durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_receipt_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_materialization_work_selection_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT;
    replay_floor BIGINT;
    exact_evidence BOOLEAN := FALSE;
    ready_exists BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.outcome <> 'selecting' THEN
            RAISE EXCEPTION 'materialization selection must begin as a provisional reservation'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_selection_reservation_first';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.outcome <> 'selecting'
        OR NEW.selection_id IS DISTINCT FROM OLD.selection_id
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.requested_at_ms IS DISTINCT FROM OLD.requested_at_ms
        OR NEW.duration_ms IS DISTINCT FROM OLD.duration_ms
        OR NEW.outcome = 'selecting'
    THEN
        RAISE EXCEPTION 'materialization selection transition is immutable or invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_transition';
    END IF;
    SELECT replay_floor_ms INTO replay_floor
    FROM workflow_plan_v2_work_selection_replay_horizons
    WHERE queue_name = 'materialization'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'materialization selection replay authority is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_horizon_required';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NEW.requested_at_ms <= replay_floor
        OR NEW.requested_at_ms < database_now - 60000
        OR NEW.requested_at_ms > database_now + 60000
    THEN
        RAISE EXCEPTION 'materialization selection request is outside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_request_time';
    END IF;
    IF NEW.claimed_at_ms > database_now
        OR database_now - NEW.claimed_at_ms > 60000
        OR (NEW.outcome <> 'quarantined' AND (
            NEW.expires_at_ms <= database_now
            OR NEW.expires_at_ms - database_now < 1000
        ))
    THEN
        RAISE EXCEPTION 'materialization selection issue time is not database-current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_database_time';
    END IF;

    IF NEW.outcome = 'claimed' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_materialization_claims AS claim
            JOIN workflow_plan_v2_instances AS instance
              ON instance.id = claim.instance_id
            JOIN workflow_runs AS run ON run.id = instance.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE claim.instance_id = NEW.instance_id
              AND repository.tenant_id = NEW.tenant_id
              AND instance.run_id = NEW.run_id
              AND instance.invocation_id = NEW.invocation_id
              AND instance.logical_job_id = NEW.logical_job_id
              AND claim.origin_selection_id = NEW.selection_id
              AND claim.owner_id = NEW.owner_id
              AND claim.generation = NEW.generation
              AND claim.descriptor_digest = NEW.authority_digest
              AND claim.claimed_at_ms = NEW.claimed_at_ms
              AND claim.expires_at_ms = NEW.expires_at_ms
              AND claim.state = 'materializing'
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_materialization_work_quarantines AS quarantine
            WHERE quarantine.instance_id = NEW.instance_id
              AND quarantine.tenant_id = NEW.tenant_id
              AND quarantine.run_id = NEW.run_id
              AND quarantine.invocation_id = NEW.invocation_id
              AND quarantine.logical_job_id = NEW.logical_job_id
              AND quarantine.selection_id = NEW.selection_id
              AND quarantine.selection_owner_id = NEW.owner_id
              AND quarantine.selection_requested_at_ms = NEW.requested_at_ms
              AND quarantine.selection_duration_ms = NEW.duration_ms
              AND quarantine.selection_generation = NEW.generation
              AND quarantine.selection_claimed_at_ms = NEW.claimed_at_ms
              AND quarantine.selection_expires_at_ms = NEW.expires_at_ms
              AND quarantine.authority_digest = NEW.authority_digest
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'contended' THEN
        exact_evidence := TRUE;
    ELSE
        SELECT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_instances AS instance
            JOIN workflow_plan_v2_activation_publications AS activation_publication
              ON activation_publication.run_id = instance.run_id
             AND activation_publication.invocation_id = instance.invocation_id
             AND activation_publication.logical_job_id = instance.logical_job_id
            JOIN workflow_plan_v2_jobs AS job ON job.id = instance.logical_job_id
            JOIN workflow_plan_v2_invocations AS invocation
              ON invocation.run_id = instance.run_id
             AND invocation.id = instance.invocation_id
            JOIN workflow_plan_v2_runs AS marker ON marker.run_id = instance.run_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            LEFT JOIN workflow_plan_v2_materialization_claims AS claim
              ON claim.instance_id = instance.id
            LEFT JOIN workflow_plan_v2_materialization_work_quarantines AS quarantine
              ON quarantine.instance_id = instance.id
            WHERE activation_publication.condition_matched
              AND activation_publication.instance_count > 0
              AND job.state = 'activated'
              AND automata_workflow_plan_v2_invocation_published(
                  marker.run_id, invocation.id
              )
              AND invocation.state IN ('pending', 'active')
              AND marker.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress')
              AND quarantine.instance_id IS NULL
              AND (claim.instance_id IS NULL OR (
                  claim.state = 'materializing'
                  AND claim.expires_at_ms <= NEW.claimed_at_ms
              ))
        ) INTO ready_exists;
        exact_evidence := NOT ready_exists;
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'materialization selection lacks exact durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_receipt_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

-- OIDC currentness binds the immutable run origin to the executing invocation.
-- A child's plan digest is catalog-bound rather than the root run plan digest.
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
              OR origin.origin_kind = 'scheduled_fire'
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
              OR origin.origin_kind = 'scheduled_fire'
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
          OR origin.origin_kind = 'scheduled_fire'
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
          AND origin.origin_kind IN ('provider_delivery', 'scheduled_fire')
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
          AND origin.origin_kind IN ('provider_delivery', 'scheduled_fire')
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
