-- Wave 1 EVT-02 append-only migration 0038. Earlier applied versions remain frozen.

ALTER TABLE github_server_service_authorities
    DROP CONSTRAINT github_server_service_authorities_permission_exact,
    DROP CONSTRAINT github_server_service_authorities_service_scope;

ALTER TABLE github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_permission_exact CHECK (
        (service_scope = 'checks_write'
            AND permission_policy = '{"checks": "write"}'::jsonb
            AND policy_digest = decode(
                '6acf4ef0f49f5935d65a42dacb8ffcd49718dfd847d802d96038d81cea869a9c',
                'hex'
            ))
        OR (service_scope = 'private_repository_source_read'
            AND permission_policy = '{"contents": "read"}'::jsonb
            AND policy_digest = decode(
                '3c2516eac095f5bda3e7d20265497325e91030d1abe5907d4fb7fefcd0aa7f57',
                'hex'
            ))
        OR (service_scope = 'workflow_permissions_read'
            AND permission_policy = '{"administration": "read"}'::jsonb
            AND policy_digest = decode(
                '8ed2a0af82c45da675ac00d905c42d8da14c97ea67427c43cc00c60a6c330a30',
                'hex'
            ))
        OR (service_scope = 'private_pull_request_files_read'
            AND permission_policy = '{"pull_requests": "read"}'::jsonb
            AND policy_digest = decode(
                '523d0319f40cf91e5eb3e1482a80462088748aa2537ae3c9540e76b7965d0099',
                'hex'
            ))
    ),
    ADD CONSTRAINT github_server_service_authorities_service_scope CHECK (
        service_scope = ANY (ARRAY[
            'checks_write'::text,
            'private_repository_source_read'::text,
            'workflow_permissions_read'::text,
            'private_pull_request_files_read'::text
        ])
    );

ALTER TABLE github_server_service_authority_handoffs
    DROP CONSTRAINT github_server_service_handoffs_action;

ALTER TABLE github_server_service_authority_handoffs
    ADD CONSTRAINT github_server_service_handoffs_action CHECK (
        consumer_action = ANY (ARRAY[
            'ensure_check_suite'::text,
            'create_check_run'::text,
            'reconcile_check_run'::text,
            'publish_check_run'::text,
            'fetch_private_repository_revision'::text,
            'fetch_private_repository_changed_files'::text,
            'discover_private_repository_schedules'::text,
            'observe_workflow_permission_defaults'::text,
            'fetch_private_pull_request_files'::text
        ])
    );

ALTER TABLE github_provider_delivery_evidence
    ADD COLUMN private_pull_request_files_authority_id UUID,
    ADD COLUMN private_pull_request_files_authority_identity_digest BYTEA,
    ADD COLUMN private_pull_request_files_authority_app_configuration_revision BIGINT,
    ADD COLUMN private_pull_request_files_authority_policy_revision BIGINT;

ALTER TABLE github_provider_delivery_evidence
    ADD CONSTRAINT github_provider_delivery_evidence_pr_files_authority
        FOREIGN KEY (private_pull_request_files_authority_id)
        REFERENCES github_server_service_authorities (id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT github_provider_delivery_evidence_pr_files_selector_shape CHECK (
        repository_visibility = 'private'
        AND authenticated_event_name = 'pull_request'
        AND private_pull_request_files_authority_id IS NOT NULL
        AND private_pull_request_files_authority_identity_digest IS NOT NULL
        AND octet_length(private_pull_request_files_authority_identity_digest) = 32
        AND private_pull_request_files_authority_app_configuration_revision > 0
        AND private_pull_request_files_authority_policy_revision > 0
        AND private_pull_request_files_authority_id <> checks_authority_id
        AND private_pull_request_files_authority_identity_digest <>
            checks_authority_identity_digest
        AND private_pull_request_files_authority_id <>
            private_source_authority_id
        AND private_pull_request_files_authority_identity_digest <>
            private_source_authority_identity_digest
        OR NOT (
            repository_visibility = 'private'
            AND authenticated_event_name = 'pull_request'
        )
        AND private_pull_request_files_authority_id IS NULL
        AND private_pull_request_files_authority_identity_digest IS NULL
        AND private_pull_request_files_authority_app_configuration_revision IS NULL
        AND private_pull_request_files_authority_policy_revision IS NULL
    ) NOT VALID;

CREATE FUNCTION automata_github_provider_delivery_pr_files_authority_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    inbox provider_delivery_inbox%ROWTYPE;
    manifest_pin RECORD;
    authority github_server_service_authorities%ROWTYPE;
BEGIN
    IF NEW.repository_visibility <> 'private'
        OR NEW.authenticated_event_name <> 'pull_request'
    THEN
        RETURN NEW;
    END IF;

    SELECT * INTO inbox
    FROM provider_delivery_inbox
    WHERE id = NEW.provider_delivery_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;

    SELECT manifest_source.*,
           current_source.activated_at_ms AS current_activated_at_ms
      INTO manifest_pin
    FROM github_provider_manifest_revisions AS manifest_source
    JOIN github_provider_manifest_current AS current_source
      ON current_source.tenant_id = manifest_source.tenant_id
     AND current_source.repository_id = manifest_source.repository_id
     AND current_source.provider_connection_id =
         manifest_source.provider_connection_id
     AND current_source.manifest_revision = manifest_source.manifest_revision
     AND current_source.manifest_digest = manifest_source.manifest_digest
    WHERE manifest_source.tenant_id = NEW.tenant_id
      AND manifest_source.repository_id = NEW.repository_id
      AND manifest_source.provider_connection_id = NEW.provider_connection_id
      AND manifest_source.manifest_revision = NEW.provider_manifest_revision
      AND manifest_source.manifest_digest = NEW.provider_manifest_digest
    FOR SHARE OF manifest_source, current_source;

    SELECT * INTO authority
    FROM github_server_service_authorities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.private_pull_request_files_authority_id
    FOR SHARE;

    IF inbox.id IS NULL
        OR manifest_pin.provider_connection_id IS NULL
        OR authority.id IS NULL
        OR inbox.repository_visibility <> 'private'
        OR inbox.accepted_at_ms < manifest_pin.current_activated_at_ms
        OR authority.repository_id <> NEW.repository_id
        OR authority.provider_connection_id <> NEW.provider_connection_id
        OR authority.provider_installation_id <> NEW.provider_installation_id
        OR authority.github_app_id <> manifest_pin.github_app_id
        OR authority.github_repository_id <> NEW.github_repository_id
        OR authority.github_repository_name <> NEW.github_repository_name
        OR authority.service_scope <> 'private_pull_request_files_read'
        OR authority.github_app_client_id <> manifest_pin.github_app_client_id
        OR authority.github_app_jwt_issuer_kind <>
            manifest_pin.github_app_jwt_issuer_kind
        OR authority.app_key_spki_sha256 <> manifest_pin.app_key_spki_sha256
        OR authority.app_configuration_revision <>
            NEW.private_pull_request_files_authority_app_configuration_revision
        OR authority.app_configuration_revision <>
            manifest_pin.app_configuration_revision
        OR authority.policy_revision <>
            NEW.private_pull_request_files_authority_policy_revision
        OR authority.policy_revision <> manifest_pin.policy_revision
        OR authority.identity_digest <>
            NEW.private_pull_request_files_authority_identity_digest
        OR authority.state <> 'active'
        OR authority.created_at_ms > inbox.accepted_at_ms
    THEN
        RAISE EXCEPTION 'private pull-request files authority is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT =
                      'github_provider_delivery_evidence_pr_files_authority_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER github_provider_delivery_evidence_01_pr_files_guard
BEFORE INSERT ON github_provider_delivery_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_delivery_pr_files_authority_guard();

CREATE OR REPLACE FUNCTION automata_github_server_service_handoff_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    issuance github_server_service_authority_issuances%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    check_outbox github_check_projection_outbox%ROWTYPE;
    check_subject github_check_subjects%ROWTYPE;
    delivery provider_delivery_inbox%ROWTYPE;
    delivery_evidence github_provider_delivery_evidence%ROWTYPE;
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
        OR NEW.required_through_ms > issuance.provider_expires_at_ms - 60000
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
            OR NEW.required_through_ms::NUMERIC >
                check_outbox.claim_expires_at_ms::NUMERIC
                + CASE NEW.consumer_action
                    WHEN 'publish_check_run' THEN 600000
                    ELSE 300000
                  END
            OR CASE NEW.consumer_action
                WHEN 'ensure_check_suite' THEN check_outbox.claim_action <> 'ensure_suite'
                WHEN 'create_check_run' THEN
                    check_outbox.claim_action <> 'prepare_run_create'
                WHEN 'reconcile_check_run' THEN
                    check_outbox.claim_action <> 'reconcile_run_create'
                WHEN 'publish_check_run' THEN check_outbox.claim_action <> 'publish'
                ELSE TRUE
               END
            OR check_subject.tenant_id <> authority.tenant_id
            OR check_subject.repository_id <> authority.repository_id
            OR check_subject.provider_connection_id <>
                authority.provider_connection_id
            OR check_subject.provider_installation_id <>
                authority.provider_installation_id
            OR check_subject.github_app_id <> authority.github_app_id
            OR check_subject.github_repository_id <> authority.github_repository_id
            OR check_subject.github_repository_name <>
                authority.github_repository_name
        THEN
            RAISE EXCEPTION 'GitHub Checks handoff consumer claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT =
                          'github_server_service_handoffs_checks_claim_exact';
        END IF;
    ELSIF authority.service_scope = 'private_repository_source_read' THEN
        IF NEW.consumer_action = 'discover_private_repository_schedules' THEN
            SELECT EXISTS (
                SELECT 1
                  FROM github_schedule_discovery_claims AS discovery
                  JOIN github_provider_manifest_current AS current
                    ON current.tenant_id = discovery.tenant_id
                   AND current.repository_id = discovery.repository_id
                   AND current.provider_connection_id =
                       discovery.provider_connection_id
                   AND current.manifest_revision = discovery.manifest_revision
                   AND current.manifest_digest = discovery.manifest_digest
                  JOIN github_provider_manifest_revisions AS manifest
                    ON manifest.tenant_id = current.tenant_id
                   AND manifest.repository_id = current.repository_id
                   AND manifest.provider_connection_id =
                       current.provider_connection_id
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
                   AND discovery.provider_connection_id =
                       authority.provider_connection_id
                   AND discovery.source_authority_kind =
                       'private_repository_source_read'
                   AND discovery.private_source_authority_id = authority.id
                   AND discovery.private_source_authority_identity_digest =
                       authority.identity_digest
                   AND discovery.private_source_authority_app_configuration_revision =
                       authority.app_configuration_revision
                   AND discovery.private_source_authority_policy_revision =
                       authority.policy_revision
                   AND manifest.provider_installation_id =
                       authority.provider_installation_id
                   AND manifest.github_app_id = authority.github_app_id
                   AND manifest.github_repository_id = authority.github_repository_id
                   AND manifest.github_repository_name =
                       authority.github_repository_name
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
                OR NEW.required_through_ms::NUMERIC >
                    delivery.claim_expires_at_ms::NUMERIC + 300000
                OR NEW.consumer_action NOT IN (
                    'fetch_private_repository_revision',
                    'fetch_private_repository_changed_files'
                )
                OR delivery.tenant_id IS DISTINCT FROM authority.tenant_id
                OR delivery.provider IS DISTINCT FROM 'github'
                OR delivery.repository_visibility IS DISTINCT FROM 'private'
                OR delivery.connection_id IS DISTINCT FROM
                    authority.provider_connection_id
                OR delivery.installation_id IS DISTINCT FROM
                    authority.provider_installation_id
                OR delivery.provider_repository_id IS DISTINCT FROM
                    authority.github_repository_id
                OR delivery.repository_identity IS DISTINCT FROM
                    authority.github_repository_name
                OR repository.scm_provider IS DISTINCT FROM 'github'
                OR repository.provider_repository_id IS DISTINCT FROM
                    authority.github_repository_id::TEXT
                OR repository.owner || '/' || repository.name IS DISTINCT FROM
                    authority.github_repository_name
            THEN
                RAISE EXCEPTION 'private GitHub source handoff consumer claim is not exact'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT =
                              'github_server_service_handoffs_source_claim_exact';
            END IF;
        END IF;
    ELSIF authority.service_scope = 'private_pull_request_files_read' THEN
        SELECT * INTO delivery
        FROM provider_delivery_inbox
        WHERE id = NEW.consumer_id
        FOR SHARE;
        SELECT * INTO delivery_evidence
        FROM github_provider_delivery_evidence
        WHERE provider_delivery_id = NEW.consumer_id
          AND tenant_id = authority.tenant_id
        FOR SHARE;
        SELECT * INTO repository
        FROM repositories
        WHERE id = authority.repository_id
          AND tenant_id = authority.tenant_id
        FOR SHARE;
        IF delivery.id IS NULL
            OR delivery_evidence.provider_delivery_id IS NULL
            OR repository.id IS NULL
            OR NEW.consumer_action <> 'fetch_private_pull_request_files'
            OR delivery.state IS DISTINCT FROM 'claimed'
            OR delivery.claim_owner_id IS DISTINCT FROM NEW.consumer_owner_id
            OR delivery.claim_fence IS DISTINCT FROM NEW.consumer_claim_fence
            OR delivery.attempt_count IS DISTINCT FROM NEW.consumer_revision
            OR delivery.claimed_at_ms IS NULL
            OR delivery.claim_expires_at_ms IS NULL
            OR delivery.claimed_at_ms > NEW.granted_at_ms
            OR delivery.state_updated_at_ms > NEW.granted_at_ms
            OR delivery.claim_expires_at_ms <= NEW.granted_at_ms
            OR NEW.required_through_ms::NUMERIC >
                delivery.claim_expires_at_ms::NUMERIC + 300000
            OR delivery.tenant_id IS DISTINCT FROM authority.tenant_id
            OR delivery.provider IS DISTINCT FROM 'github'
            OR delivery.repository_visibility IS DISTINCT FROM 'private'
            OR delivery.connection_id IS DISTINCT FROM
                authority.provider_connection_id
            OR delivery.installation_id IS DISTINCT FROM
                authority.provider_installation_id
            OR delivery.provider_repository_id IS DISTINCT FROM
                authority.github_repository_id
            OR delivery.repository_identity IS DISTINCT FROM
                authority.github_repository_name
            OR delivery_evidence.authenticated_event_name IS DISTINCT FROM 'pull_request'
            OR delivery_evidence.private_pull_request_files_authority_id IS DISTINCT FROM
                authority.id
            OR delivery_evidence.private_pull_request_files_authority_identity_digest IS DISTINCT FROM
                authority.identity_digest
            OR delivery_evidence.private_pull_request_files_authority_app_configuration_revision IS DISTINCT FROM
                authority.app_configuration_revision
            OR delivery_evidence.private_pull_request_files_authority_policy_revision IS DISTINCT FROM
                authority.policy_revision
            OR repository.scm_provider IS DISTINCT FROM 'github'
            OR repository.provider_repository_id IS DISTINCT FROM
                authority.github_repository_id::TEXT
            OR repository.owner || '/' || repository.name IS DISTINCT FROM
                authority.github_repository_name
        THEN
            RAISE EXCEPTION 'private GitHub pull-request files handoff claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT =
                          'github_server_service_handoffs_pr_files_claim_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub server-service handoff scope is unknown'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_handoffs_scope_exact';
    END IF;
    RETURN NEW;
END;
$$;
