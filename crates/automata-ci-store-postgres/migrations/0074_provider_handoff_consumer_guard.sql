-- Server-service handoffs must follow the provider-neutral consumer records
-- introduced after the original GitHub Checks and delivery queues. Keep the
-- database insert guard on the same exact claims revalidated by the Rust port.
CREATE OR REPLACE FUNCTION automata_github_server_service_handoff_insert_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    issuance github_server_service_authority_issuances%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    consumer_exact BOOLEAN;
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
        SELECT EXISTS (
            SELECT 1
            FROM provider_result_outbox AS outbox
            JOIN provider_result_subjects AS subject
              ON subject.subject_id = outbox.subject_id
            JOIN provider_connection_revisions AS provider_connection
              ON provider_connection.connection_id = subject.connection_id
             AND provider_connection.revision = subject.connection_revision
             AND provider_connection.manifest_digest = subject.connection_digest
            JOIN provider_instance_revisions AS provider_instance
              ON provider_instance.instance_id =
                    provider_connection.provider_instance_id
             AND provider_instance.revision = provider_connection.provider_revision
             AND provider_instance.configuration_digest =
                    provider_connection.provider_configuration_digest
             AND provider_instance.capability_digest =
                    provider_connection.capability_digest
            JOIN repositories AS repository
              ON repository.id = authority.repository_id
             AND repository.tenant_id = provider_connection.workspace_id
             AND repository.scm_provider = provider_instance.provider_type
             AND repository.provider_repository_id =
                    provider_connection.external_repository_id
            WHERE outbox.subject_id = NEW.consumer_id
              AND outbox.generation = NEW.consumer_revision
              AND outbox.state = 'claimed'
              AND outbox.claim_worker_id = NEW.consumer_owner_id
              AND outbox.claim_fence = NEW.consumer_claim_fence
              AND outbox.claim_started_at_ms <= observed_at_ms
              AND outbox.claim_expires_at_ms > observed_at_ms
              AND NEW.required_through_ms::NUMERIC <=
                    outbox.claim_expires_at_ms::NUMERIC
                    + CASE NEW.consumer_action
                        WHEN 'publish_check_run' THEN 600000
                        ELSE 300000
                      END
              AND NEW.consumer_action IN (
                    'ensure_check_suite',
                    'create_check_run',
                    'reconcile_check_run',
                    'publish_check_run'
              )
              AND subject.connection_id = authority.provider_connection_id
              AND provider_connection.workspace_id = authority.tenant_id
              AND provider_instance.provider_type = 'github'
              AND provider_connection.external_repository_id =
                    authority.github_repository_id::TEXT
            FOR SHARE OF outbox, subject, provider_connection,
                provider_instance, repository
        ) INTO consumer_exact;

        IF consumer_exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'GitHub result handoff consumer claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT =
                          'github_server_service_handoffs_checks_claim_exact';
        END IF;
    ELSIF authority.service_scope = 'repository_contents_read' THEN
        IF NEW.consumer_action = 'discover_repository_schedules' THEN
            SELECT EXISTS (
                SELECT 1
                FROM github_schedule_discovery_claims AS discovery
                JOIN github_provider_manifest_current AS current_manifest
                  ON current_manifest.tenant_id = discovery.tenant_id
                 AND current_manifest.repository_id = discovery.repository_id
                 AND current_manifest.provider_connection_id =
                        discovery.provider_connection_id
                 AND current_manifest.manifest_revision = discovery.manifest_revision
                 AND current_manifest.manifest_digest = discovery.manifest_digest
                JOIN github_provider_manifest_revisions AS manifest
                  ON manifest.tenant_id = current_manifest.tenant_id
                 AND manifest.repository_id = current_manifest.repository_id
                 AND manifest.provider_connection_id =
                        current_manifest.provider_connection_id
                 AND manifest.manifest_revision = current_manifest.manifest_revision
                 AND manifest.manifest_digest = current_manifest.manifest_digest
                JOIN repositories AS repository
                  ON repository.id = discovery.repository_id
                 AND repository.tenant_id = discovery.tenant_id
                 AND repository.scm_provider = 'github'
                 AND repository.provider_repository_id =
                        manifest.github_repository_id::TEXT
                WHERE discovery.discovery_id = NEW.consumer_id
                  AND discovery.state = 'claimed'
                  AND discovery.claim_owner_id = NEW.consumer_owner_id
                  AND discovery.claim_fence = NEW.consumer_claim_fence
                  AND NEW.consumer_revision = 1
                  AND discovery.claimed_at_ms <= observed_at_ms
                  AND discovery.updated_at_ms <= observed_at_ms
                  AND discovery.claim_expires_at_ms > observed_at_ms
                  AND NEW.required_through_ms::NUMERIC <=
                        discovery.claim_expires_at_ms::NUMERIC + 300000
                  AND discovery.tenant_id = authority.tenant_id
                  AND discovery.repository_id = authority.repository_id
                  AND discovery.provider_connection_id =
                        authority.provider_connection_id
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
                  AND manifest.github_repository_name =
                        authority.github_repository_name
                FOR SHARE OF discovery, current_manifest, manifest, repository
            ) INTO consumer_exact;
        ELSIF NEW.consumer_action = 'resolve_workflow_dispatch_source' THEN
            SELECT EXISTS (
                SELECT 1
                FROM workflow_dispatch_source_resolutions AS resolution
                JOIN github_provider_manifest_current AS current_manifest
                  ON current_manifest.tenant_id = resolution.tenant_id
                 AND current_manifest.repository_id = resolution.repository_id
                 AND current_manifest.provider_connection_id =
                        resolution.provider_connection_id
                 AND current_manifest.manifest_revision =
                        resolution.provider_manifest_revision
                 AND current_manifest.manifest_digest =
                        resolution.provider_manifest_digest
                JOIN github_provider_manifest_revisions AS manifest
                  ON manifest.tenant_id = current_manifest.tenant_id
                 AND manifest.repository_id = current_manifest.repository_id
                 AND manifest.provider_connection_id =
                        current_manifest.provider_connection_id
                 AND manifest.manifest_revision = current_manifest.manifest_revision
                 AND manifest.manifest_digest = current_manifest.manifest_digest
                WHERE resolution.tenant_id = authority.tenant_id
                  AND resolution.operation_id = NEW.consumer_id
                  AND resolution.repository_id = authority.repository_id
                  AND resolution.state = 'claimed'
                  AND resolution.claim_owner_id = NEW.consumer_owner_id
                  AND resolution.claim_fence = NEW.consumer_claim_fence
                  AND NEW.consumer_revision = 1
                  AND resolution.claimed_at_ms <= observed_at_ms
                  AND resolution.claim_expires_at_ms > observed_at_ms
                  AND NEW.required_through_ms::NUMERIC <=
                        resolution.claim_expires_at_ms::NUMERIC + 300000
                  AND resolution.repository_contents_authority_id = authority.id
                  AND resolution.repository_contents_authority_identity_digest =
                        authority.identity_digest
                  AND resolution.repository_contents_authority_app_configuration_revision =
                        authority.app_configuration_revision
                  AND resolution.repository_contents_authority_policy_revision =
                        authority.policy_revision
                  AND manifest.repository_visibility = 'private'
                  AND manifest.provider_installation_id =
                        authority.provider_installation_id
                  AND manifest.github_app_id = authority.github_app_id
                  AND manifest.github_repository_id = authority.github_repository_id
                  AND manifest.github_repository_name =
                        authority.github_repository_name
                  AND manifest.app_configuration_revision =
                        authority.app_configuration_revision
                  AND manifest.policy_revision = authority.policy_revision
                FOR SHARE OF resolution, current_manifest, manifest
            ) INTO consumer_exact;
        ELSE
            SELECT EXISTS (
                SELECT 1
                FROM provider_processing_invocations AS invocation
                JOIN provider_deliveries AS delivery
                  ON delivery.delivery_id = invocation.source_delivery_id
                 AND delivery.disposition = 'trigger'
                JOIN provider_connection_revisions AS provider_connection
                  ON provider_connection.connection_id = delivery.connection_id
                 AND provider_connection.revision = delivery.connection_revision
                 AND provider_connection.provider_instance_id =
                        delivery.provider_instance_id
                 AND provider_connection.provider_revision =
                        delivery.provider_revision
                 AND provider_connection.external_repository_id =
                        delivery.repository_external_id
                JOIN provider_instance_revisions AS provider_instance
                  ON provider_instance.instance_id = delivery.provider_instance_id
                 AND provider_instance.revision = delivery.provider_revision
                 AND provider_instance.provider_type = delivery.provider_type
                 AND provider_instance.configuration_digest =
                        provider_connection.provider_configuration_digest
                 AND provider_instance.capability_digest =
                        provider_connection.capability_digest
                JOIN repositories AS repository
                  ON repository.id = authority.repository_id
                 AND repository.tenant_id = provider_connection.workspace_id
                 AND repository.scm_provider = provider_instance.provider_type
                 AND repository.provider_repository_id =
                        provider_connection.external_repository_id
                WHERE invocation.invocation_id = NEW.consumer_id
                  AND invocation.state = 'claimed'
                  AND invocation.claim_worker_id = NEW.consumer_owner_id
                  AND invocation.claim_fence = NEW.consumer_claim_fence
                  AND invocation.attempts = NEW.consumer_revision
                  AND invocation.claim_started_at_ms <= observed_at_ms
                  AND invocation.claim_expires_at_ms > observed_at_ms
                  AND NEW.required_through_ms::NUMERIC <=
                        invocation.claim_expires_at_ms::NUMERIC + 300000
                  AND NEW.consumer_action IN (
                        'fetch_repository_revision',
                        'fetch_repository_changed_files'
                  )
                  AND provider_connection.workspace_id = authority.tenant_id
                  AND provider_connection.connection_id =
                        authority.provider_connection_id
                  AND provider_instance.provider_type = 'github'
                  AND provider_connection.external_repository_id =
                        authority.github_repository_id::TEXT
                  AND delivery.repository_external_id =
                        authority.github_repository_id::TEXT
                FOR SHARE OF invocation, delivery, provider_connection,
                    provider_instance, repository
            ) INTO consumer_exact;
        END IF;

        IF consumer_exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'private GitHub source handoff consumer claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT =
                          'github_server_service_handoffs_source_claim_exact';
        END IF;
    ELSIF authority.service_scope = 'pull_requests_read' THEN
        SELECT EXISTS (
            SELECT 1
            FROM provider_processing_invocations AS invocation
            JOIN provider_deliveries AS delivery
              ON delivery.delivery_id = invocation.source_delivery_id
             AND delivery.disposition = 'trigger'
            JOIN provider_connection_revisions AS provider_connection
              ON provider_connection.connection_id = delivery.connection_id
             AND provider_connection.revision = delivery.connection_revision
             AND provider_connection.provider_instance_id =
                    delivery.provider_instance_id
             AND provider_connection.provider_revision = delivery.provider_revision
             AND provider_connection.external_repository_id =
                    delivery.repository_external_id
            JOIN provider_instance_revisions AS provider_instance
              ON provider_instance.instance_id = delivery.provider_instance_id
             AND provider_instance.revision = delivery.provider_revision
             AND provider_instance.provider_type = delivery.provider_type
             AND provider_instance.configuration_digest =
                    provider_connection.provider_configuration_digest
             AND provider_instance.capability_digest =
                    provider_connection.capability_digest
            JOIN repositories AS repository
              ON repository.id = authority.repository_id
             AND repository.tenant_id = provider_connection.workspace_id
             AND repository.scm_provider = provider_instance.provider_type
             AND repository.provider_repository_id =
                    provider_connection.external_repository_id
            WHERE invocation.invocation_id = NEW.consumer_id
              AND invocation.state = 'claimed'
              AND invocation.claim_worker_id = NEW.consumer_owner_id
              AND invocation.claim_fence = NEW.consumer_claim_fence
              AND invocation.attempts = NEW.consumer_revision
              AND invocation.claim_started_at_ms <= observed_at_ms
              AND invocation.claim_expires_at_ms > observed_at_ms
              AND NEW.required_through_ms::NUMERIC <=
                    invocation.claim_expires_at_ms::NUMERIC + 300000
              AND NEW.consumer_action = 'fetch_pull_request_files'
              AND provider_connection.workspace_id = authority.tenant_id
              AND provider_connection.connection_id =
                    authority.provider_connection_id
              AND provider_instance.provider_type = 'github'
              AND provider_connection.external_repository_id =
                    authority.github_repository_id::TEXT
              AND delivery.repository_external_id =
                    authority.github_repository_id::TEXT
              AND delivery.event_type = 'pull_request'
            FOR SHARE OF invocation, delivery, provider_connection,
                provider_instance, repository
        ) INTO consumer_exact;

        IF consumer_exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'private GitHub pull-request files handoff claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT =
                          'github_server_service_handoffs_pull_requests_claim_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub server-service handoff scope is unknown'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_handoffs_scope_exact';
    END IF;

    RETURN NEW;
END;
$$;
