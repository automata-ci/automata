-- PostgreSQL resolves an unqualified identifier against both PL/pgSQL variables
-- and table columns.  The original guard used row variables named
-- `manifest_revision` and `policy_revision`, then selected unqualified columns
-- with those same names.  Replace the guard with unambiguous row names and
-- explicit table aliases so the integrity boundary is executable on PostgreSQL
-- 18 instead of failing before it can validate an observation.

CREATE OR REPLACE FUNCTION automata_github_workflow_permission_observation_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate github_workflow_permission_observation_candidates%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    handoff github_server_service_authority_handoffs%ROWTYPE;
    candidate_authority_id uuid;
    current_manifest github_provider_manifest_current%ROWTYPE;
    current_policy workflow_runtime_policy_current%ROWTYPE;
    manifest_row github_provider_manifest_revisions%ROWTYPE;
    policy_row workflow_runtime_policy_revisions%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    SELECT observation_candidate.authority_id INTO candidate_authority_id
    FROM github_workflow_permission_observation_candidates AS observation_candidate
    WHERE observation_candidate.observation_id = NEW.observation_id
      AND observation_candidate.tenant_id = NEW.tenant_id;
    IF candidate_authority_id IS NOT NULL THEN
        SELECT service_authority.* INTO authority
        FROM github_server_service_authorities AS service_authority
        WHERE service_authority.tenant_id = NEW.tenant_id
          AND service_authority.id = candidate_authority_id
        FOR UPDATE;
    END IF;
    SELECT observation_candidate.* INTO candidate
    FROM github_workflow_permission_observation_candidates AS observation_candidate
    WHERE observation_candidate.observation_id = NEW.observation_id
      AND observation_candidate.tenant_id = NEW.tenant_id
    FOR SHARE;
    SELECT authority_handoff.* INTO handoff
    FROM github_server_service_authority_handoffs AS authority_handoff
    WHERE authority_handoff.id = NEW.handoff_id
    FOR SHARE;
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    IF candidate.observation_id IS NULL
        OR authority.id IS NULL
        OR authority.state <> 'active'
        OR authority.service_scope <> 'workflow_permissions_read'
        OR authority.identity_digest <> candidate.authority_identity_digest
        OR handoff.id IS NULL
        OR NEW.candidate_digest <> candidate.candidate_digest
        OR EXISTS (
            SELECT 1
            FROM github_workflow_permission_candidate_closures AS closure
            WHERE closure.tenant_id = candidate.tenant_id
              AND closure.observation_id = candidate.observation_id
        )
        OR NEW.repository_id <> candidate.repository_id
        OR NEW.provider_connection_id <> candidate.provider_connection_id
        OR handoff.tenant_id <> candidate.tenant_id
        OR handoff.authority_id <> candidate.authority_id
        OR handoff.generation <> NEW.handoff_generation
        OR handoff.consumer_id <> candidate.observation_id
        OR handoff.consumer_owner_id <> candidate.consumer_owner_id
        OR handoff.consumer_claim_fence <> candidate.consumer_claim_fence
        OR handoff.consumer_action <> candidate.consumer_action
        OR handoff.consumer_revision <> candidate.consumer_revision
        OR handoff.granted_at_ms > NEW.provider_observed_at_ms
        OR NEW.request_started_at_ms <> candidate.claimed_at_ms
        OR NEW.provider_observed_at_ms > handoff.required_through_ms
        OR handoff.released_at_ms IS NULL
        OR handoff.released_at_ms <> NEW.released_at_ms
        OR NEW.released_at_ms > candidate.expires_at_ms
        OR NEW.matches_expected_default <> (
            NEW.default_workflow_permissions = candidate.expected_default
            AND NEW.can_approve_pull_request_reviews =
                candidate.expected_can_approve_pull_request_reviews
        )
        OR NEW.recorded_at_ms > database_now_ms
        OR NEW.recorded_at_ms < database_now_ms - 60000
        OR NEW.observation_digest <>
            automata_github_workflow_permission_observation_digest(NEW)
    THEN
        RAISE EXCEPTION 'GitHub workflow-permission observation is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_permission_observation_exact';
    END IF;

    IF NEW.matches_expected_default THEN
        SELECT manifest_current.* INTO current_manifest
        FROM github_provider_manifest_current AS manifest_current
        WHERE manifest_current.tenant_id = candidate.tenant_id
          AND manifest_current.repository_id = candidate.repository_id
          AND manifest_current.provider_connection_id = candidate.provider_connection_id
        FOR SHARE;
        SELECT policy_current.* INTO current_policy
        FROM workflow_runtime_policy_current AS policy_current
        WHERE policy_current.tenant_id = candidate.tenant_id
          AND policy_current.repository_id = candidate.repository_id
        FOR SHARE;
        SELECT manifest_revision.* INTO manifest_row
        FROM github_provider_manifest_revisions AS manifest_revision
        WHERE manifest_revision.tenant_id = candidate.tenant_id
          AND manifest_revision.repository_id = candidate.repository_id
          AND manifest_revision.provider_connection_id = candidate.provider_connection_id
          AND manifest_revision.manifest_revision = candidate.proposed_manifest_revision
          AND manifest_revision.manifest_digest = candidate.proposed_manifest_digest
        FOR SHARE;
        SELECT policy_revision.* INTO policy_row
        FROM workflow_runtime_policy_revisions AS policy_revision
        WHERE policy_revision.tenant_id = candidate.tenant_id
          AND policy_revision.repository_id = candidate.repository_id
          AND policy_revision.policy_revision = candidate.proposed_runtime_policy_revision
          AND policy_revision.policy_digest = candidate.proposed_runtime_policy_digest
        FOR SHARE;
        -- Current-pointer locks can wait independently of the evidence locks.
        -- Re-sample before the activation freshness decision.
        database_now_ms := floor(
            extract(epoch FROM clock_timestamp()) * 1000
        )::BIGINT;
        IF current_manifest.provider_connection_id IS NULL
            OR current_policy.repository_id IS NULL
            OR manifest_row.provider_connection_id IS NULL
            OR policy_row.repository_id IS NULL
            OR current_manifest.manifest_revision <>
                candidate.proposed_manifest_revision
            OR current_manifest.manifest_digest <>
                candidate.proposed_manifest_digest
            OR current_policy.policy_revision <>
                candidate.proposed_runtime_policy_revision
            OR current_policy.policy_digest <>
                candidate.proposed_runtime_policy_digest
            OR manifest_row.provider_installation_id <>
                candidate.provider_installation_id
            OR manifest_row.github_repository_id <>
                candidate.github_repository_id
            OR manifest_row.github_repository_name <>
                candidate.github_repository_name
            OR manifest_row.github_app_id <> candidate.github_app_id
            OR manifest_row.github_app_client_id <>
                candidate.github_app_client_id
            OR manifest_row.github_app_jwt_issuer_kind <>
                candidate.github_app_jwt_issuer_kind
            OR manifest_row.app_key_spki_sha256 <>
                candidate.app_key_spki_sha256
            OR manifest_row.app_configuration_revision <>
                candidate.app_configuration_revision
            OR manifest_row.policy_revision <> candidate.policy_revision
            OR manifest_row.runtime_policy_revision <>
                candidate.proposed_runtime_policy_revision
            OR manifest_row.runtime_policy_digest <>
                candidate.proposed_runtime_policy_digest
            OR policy_row.state <> 'sealed'
            OR (
                CASE candidate.expected_default
                    WHEN 'read' THEN
                        pg_catalog.convert_from(
                            policy_row.permission_policy_canonical, 'UTF8'
                        )::jsonb -> 'provider_default'
                        IS DISTINCT FROM
                            '{"contents":"read","packages":"read"}'::jsonb
                    WHEN 'write' THEN
                        pg_catalog.convert_from(
                            policy_row.permission_policy_canonical, 'UTF8'
                        )::jsonb -> 'provider_default'
                        IS DISTINCT FROM pg_catalog.convert_from(
                            policy_row.permission_policy_canonical, 'UTF8'
                        )::jsonb -> 'write_all'
                    ELSE TRUE
                END
            )
            OR NEW.activated_manifest_revision IS DISTINCT FROM
                candidate.proposed_manifest_revision
            OR NEW.activated_manifest_digest IS DISTINCT FROM
                candidate.proposed_manifest_digest
            OR NEW.activated_runtime_policy_revision IS DISTINCT FROM
                candidate.proposed_runtime_policy_revision
            OR NEW.activated_runtime_policy_digest IS DISTINCT FROM
                candidate.proposed_runtime_policy_digest
            OR database_now_ms > candidate.expires_at_ms
        THEN
            RAISE EXCEPTION 'matching GitHub workflow-permission activation is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_workflow_permission_activation_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
