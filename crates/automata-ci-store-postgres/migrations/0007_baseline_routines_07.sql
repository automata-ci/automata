-- Canonical greenfield schema stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_guard_github_schedule_discovery_claim_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    manifest github_provider_manifest_revisions%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    observed_at_ms BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    SELECT revision.* INTO manifest
      FROM github_provider_manifest_revisions AS revision
      JOIN github_provider_manifest_current AS current
        ON current.tenant_id = revision.tenant_id
       AND current.repository_id = revision.repository_id
       AND current.provider_connection_id = revision.provider_connection_id
       AND current.manifest_revision = revision.manifest_revision
       AND current.manifest_digest = revision.manifest_digest
     WHERE revision.tenant_id = NEW.tenant_id
       AND revision.repository_id = NEW.repository_id
       AND revision.provider_connection_id = NEW.provider_connection_id
       AND revision.manifest_revision = NEW.manifest_revision
       AND revision.manifest_digest = NEW.manifest_digest
     FOR SHARE OF revision, current;
    SELECT * INTO authority
      FROM github_server_service_authorities
     WHERE tenant_id = NEW.tenant_id
       AND id = NEW.repository_contents_authority_id
     FOR SHARE;
    IF manifest.provider_connection_id IS NULL
        OR manifest.github_repository_owner_id IS NULL
        OR manifest.github_repository_owner_id <> NEW.github_repository_owner_id
        OR NEW.claimed_at_ms > observed_at_ms
        OR observed_at_ms - NEW.claimed_at_ms > 60000
        OR NEW.claim_expires_at_ms <= observed_at_ms
        OR (
            NEW.source_authority_kind = 'repository_contents_read'
            AND (
                authority.id IS NULL
                OR authority.repository_id <> NEW.repository_id
                OR authority.provider_connection_id <> NEW.provider_connection_id
                OR authority.provider_installation_id <> manifest.provider_installation_id
                OR authority.github_app_id <> manifest.github_app_id
                OR authority.github_repository_id <> manifest.github_repository_id
                OR authority.github_repository_name <> manifest.github_repository_name
                OR authority.service_scope <> 'repository_contents_read'
                OR authority.github_app_client_id <> manifest.github_app_client_id
                OR authority.github_app_jwt_issuer_kind <>
                    manifest.github_app_jwt_issuer_kind
                OR authority.app_key_spki_sha256 <> manifest.app_key_spki_sha256
                OR authority.app_configuration_revision <>
                    NEW.repository_contents_authority_app_configuration_revision
                OR authority.app_configuration_revision <> manifest.app_configuration_revision
                OR authority.policy_revision <> NEW.repository_contents_authority_policy_revision
                OR authority.policy_revision <> manifest.policy_revision
                OR authority.identity_digest <> NEW.repository_contents_authority_identity_digest
                OR authority.state <> 'active'
                OR authority.created_at_ms > NEW.claimed_at_ms
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub schedule discovery authority is not exact and live'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_discovery_authority_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_github_schedule_discovery_claim_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    observed_at_ms BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    IF TG_OP = 'DELETE'
        OR OLD.state <> 'claimed'
        OR NEW.discovery_id IS DISTINCT FROM OLD.discovery_id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.manifest_revision IS DISTINCT FROM OLD.manifest_revision
        OR NEW.manifest_digest IS DISTINCT FROM OLD.manifest_digest
        OR NEW.github_repository_owner_id IS DISTINCT FROM OLD.github_repository_owner_id
        OR NEW.source_authority_kind IS DISTINCT FROM OLD.source_authority_kind
        OR NEW.repository_contents_authority_id IS DISTINCT FROM OLD.repository_contents_authority_id
        OR NEW.repository_contents_authority_identity_digest IS DISTINCT FROM
            OLD.repository_contents_authority_identity_digest
        OR NEW.repository_contents_authority_app_configuration_revision IS DISTINCT FROM
            OLD.repository_contents_authority_app_configuration_revision
        OR NEW.repository_contents_authority_policy_revision IS DISTINCT FROM
            OLD.repository_contents_authority_policy_revision
        OR NEW.claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
        OR NEW.claim_fence IS DISTINCT FROM OLD.claim_fence
        OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
        OR NEW.claim_expires_at_ms IS DISTINCT FROM OLD.claim_expires_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.state NOT IN ('completed', 'expired')
        OR NEW.state = 'completed' AND (
            NEW.updated_at_ms >= OLD.claim_expires_at_ms
            OR observed_at_ms >= OLD.claim_expires_at_ms
        )
        OR NEW.state = 'expired' AND (
            NEW.updated_at_ms < OLD.claim_expires_at_ms
            OR observed_at_ms < OLD.claim_expires_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub schedule discovery transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_discovery_transition_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_github_schedule_fire_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'GitHub schedule fire evidence cannot be deleted'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_fire_transition_exact';
    END IF;
    IF OLD.state IN ('admitted', 'skipped', 'failed')
        OR NEW.fire_id IS DISTINCT FROM OLD.fire_id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.registry_id IS DISTINCT FROM OLD.registry_id
        OR NEW.entry_ordinal IS DISTINCT FROM OLD.entry_ordinal
        OR NEW.scheduled_at_ms IS DISTINCT FROM OLD.scheduled_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.updated_at_ms < OLD.updated_at_ms
    THEN
        RAISE EXCEPTION 'GitHub schedule fire identity or terminal evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_fire_transition_exact';
    END IF;

    IF OLD.state = 'pending' THEN
        IF NEW.state = 'claimed' THEN
            IF NEW.attempt_count <> OLD.attempt_count + 1
                OR NEW.claim_fence <> OLD.claim_fence + 1
                OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
                OR NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id
                OR NEW.failure_kind IS DISTINCT FROM OLD.failure_kind
                OR NEW.claimed_at_ms IS DISTINCT FROM NEW.updated_at_ms
                OR NEW.claimed_at_ms < OLD.next_attempt_at_ms
                OR NEW.claim_expires_at_ms - NEW.updated_at_ms > 300000
            THEN
                RAISE EXCEPTION 'pending GitHub schedule fire claim transition is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSIF NEW.state = 'failed' THEN
            IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                OR NEW.claim_fence IS DISTINCT FROM OLD.claim_fence
                OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
                OR NEW.workflow_run_id IS NOT NULL
                OR NEW.failure_kind IS DISTINCT FROM 'registry_superseded'
            THEN
                RAISE EXCEPTION 'pending GitHub schedule fire terminal transition is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSE
            RAISE EXCEPTION 'pending GitHub schedule fire state transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_schedule_fire_transition_exact';
        END IF;
    ELSIF OLD.state = 'claimed' THEN
        IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
            OR NEW.claim_fence IS DISTINCT FROM OLD.claim_fence
        THEN
            RAISE EXCEPTION 'claimed GitHub schedule fire fence is immutable'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_schedule_fire_transition_exact';
        END IF;
        IF NEW.state = 'claimed' THEN
            IF NEW.claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
                OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
                OR NEW.claim_expires_at_ms <= OLD.claim_expires_at_ms
                OR NEW.claim_expires_at_ms - NEW.updated_at_ms > 300000
                OR NEW.updated_at_ms >= OLD.claim_expires_at_ms
                OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
                OR NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id
                OR NEW.failure_kind IS DISTINCT FROM OLD.failure_kind
            THEN
                RAISE EXCEPTION 'GitHub schedule fire renewal is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSIF NEW.state = 'pending' THEN
            IF NEW.claim_owner_id IS NOT NULL
                OR NEW.claimed_at_ms IS NOT NULL
                OR NEW.claim_expires_at_ms IS NOT NULL
                OR NEW.next_attempt_at_ms < NEW.updated_at_ms
                OR NEW.workflow_run_id IS NOT NULL
                OR NEW.failure_kind IS NOT NULL
            THEN
                RAISE EXCEPTION 'GitHub schedule fire retry transition is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSIF NEW.state IN ('admitted', 'skipped', 'failed') THEN
            IF NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
                OR (
                    NEW.failure_kind IS DISTINCT FROM 'registry_superseded'
                    AND NEW.failure_kind IS DISTINCT FROM
                        'github.schedule.attempts_exhausted'
                    AND NEW.updated_at_ms >= OLD.claim_expires_at_ms
                )
                OR NEW.failure_kind = 'github.schedule.attempts_exhausted'
                   AND OLD.attempt_count <> 20
            THEN
                RAISE EXCEPTION 'GitHub schedule fire completion transition is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSE
            RAISE EXCEPTION 'claimed GitHub schedule fire state transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_schedule_fire_transition_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub schedule fire state is unsupported'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_fire_transition_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_github_schedule_registry_entry_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM 1
      FROM github_schedule_registry_revisions
     WHERE registry_id = NEW.registry_id
     FOR KEY SHARE;
    IF EXISTS (
        SELECT 1 FROM github_schedule_registry_seals
        WHERE registry_id = NEW.registry_id
    ) THEN
        RAISE EXCEPTION 'sealed GitHub schedule registry cannot accept entries'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_entry_after_seal';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_github_schedule_registry_revision_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    manifest github_provider_manifest_revisions%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    discovery github_schedule_discovery_claims%ROWTYPE;
    observed_at_ms BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    SELECT * INTO discovery
      FROM github_schedule_discovery_claims
     WHERE discovery_id = NEW.discovery_id
     FOR UPDATE;
    IF discovery.discovery_id IS NULL
        OR discovery.state <> 'claimed'
        OR discovery.claimed_at_ms > NEW.discovered_at_ms
        OR NEW.discovered_at_ms >= discovery.claim_expires_at_ms
        OR observed_at_ms >= discovery.claim_expires_at_ms
        OR discovery.tenant_id <> NEW.tenant_id
        OR discovery.repository_id <> NEW.repository_id
        OR discovery.provider_connection_id <> NEW.provider_connection_id
        OR discovery.manifest_revision <> NEW.manifest_revision
        OR discovery.manifest_digest <> NEW.manifest_digest
        OR discovery.github_repository_owner_id <> NEW.github_repository_owner_id
        OR discovery.source_authority_kind <> NEW.source_authority_kind
        OR discovery.repository_contents_authority_id IS DISTINCT FROM
            NEW.repository_contents_authority_id
        OR discovery.repository_contents_authority_identity_digest IS DISTINCT FROM
            NEW.repository_contents_authority_identity_digest
        OR discovery.repository_contents_authority_app_configuration_revision IS DISTINCT FROM
            NEW.repository_contents_authority_app_configuration_revision
        OR discovery.repository_contents_authority_policy_revision IS DISTINCT FROM
            NEW.repository_contents_authority_policy_revision
    THEN
        RAISE EXCEPTION 'GitHub schedule registry lacks an exact live discovery claim'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_discovery_claim_exact';
    END IF;
    SELECT revision.* INTO manifest
      FROM github_provider_manifest_revisions AS revision
      JOIN github_provider_manifest_current AS current
        ON current.tenant_id = revision.tenant_id
       AND current.repository_id = revision.repository_id
       AND current.provider_connection_id = revision.provider_connection_id
       AND current.manifest_revision = revision.manifest_revision
       AND current.manifest_digest = revision.manifest_digest
     WHERE revision.tenant_id = NEW.tenant_id
       AND revision.repository_id = NEW.repository_id
       AND revision.provider_connection_id = NEW.provider_connection_id
       AND revision.manifest_revision = NEW.manifest_revision
       AND revision.manifest_digest = NEW.manifest_digest
     FOR SHARE OF revision, current;
    IF manifest.provider_connection_id IS NULL
        OR manifest.github_repository_owner_id IS NULL
        OR manifest.github_repository_owner_id <> NEW.github_repository_owner_id
        OR manifest.git_ref <> NEW.default_branch_ref
    THEN
        RAISE EXCEPTION 'GitHub schedule registry lacks its exact current manifest'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_source_authority_exact';
    END IF;

    SELECT * INTO authority
      FROM github_server_service_authorities
     WHERE tenant_id = NEW.tenant_id
       AND id = NEW.repository_contents_authority_id
     FOR SHARE;
    IF (
        NEW.source_authority_kind = 'repository_contents_read'
        AND (
            authority.id IS NULL
            OR authority.repository_id <> NEW.repository_id
            OR authority.provider_connection_id <> NEW.provider_connection_id
            OR authority.provider_installation_id <> manifest.provider_installation_id
            OR authority.github_app_id <> manifest.github_app_id
            OR authority.github_repository_id <> manifest.github_repository_id
            OR authority.github_repository_name <> manifest.github_repository_name
            OR authority.service_scope <> 'repository_contents_read'
            OR authority.github_app_client_id <> manifest.github_app_client_id
            OR authority.github_app_jwt_issuer_kind <>
                manifest.github_app_jwt_issuer_kind
            OR authority.app_key_spki_sha256 <> manifest.app_key_spki_sha256
            OR authority.app_configuration_revision <>
                NEW.repository_contents_authority_app_configuration_revision
            OR authority.app_configuration_revision <> manifest.app_configuration_revision
            OR authority.policy_revision <> NEW.repository_contents_authority_policy_revision
            OR authority.policy_revision <> manifest.policy_revision
            OR authority.identity_digest <> NEW.repository_contents_authority_identity_digest
            OR authority.state <> 'active'
            OR authority.created_at_ms > NEW.discovered_at_ms
        )
    ) THEN
        RAISE EXCEPTION 'GitHub schedule registry source authority is not exact and live'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_source_authority_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_provider_delivery_workflow_inventory() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    inbox provider_delivery_inbox%ROWTYPE;
    manifest_digest BYTEA;
BEGIN
    SELECT * INTO inbox
    FROM provider_delivery_inbox
    WHERE id = NEW.inbox_id AND tenant_id = NEW.tenant_id
    FOR SHARE;
    SELECT evidence.provider_manifest_digest INTO manifest_digest
    FROM github_provider_delivery_evidence AS evidence
    WHERE evidence.provider_delivery_id = NEW.inbox_id
      AND evidence.tenant_id = NEW.tenant_id
    FOR SHARE;
    IF inbox.id IS NULL
        OR manifest_digest IS NULL
        OR inbox.state <> 'claimed'
        OR NEW.registered_at_ms < inbox.claimed_at_ms
        OR NEW.registered_at_ms >= inbox.claim_expires_at_ms
        OR NEW.manifest_digest <> manifest_digest
    THEN
        RAISE EXCEPTION 'provider delivery workflow inventory lacks live authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_inventory_live_authority';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_provider_delivery_workflow_inventory_entry() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    inbox_state TEXT;
BEGIN
    SELECT inbox.state INTO inbox_state
    FROM provider_delivery_inbox AS inbox
    JOIN provider_delivery_workflow_inventories AS inventory
      ON inventory.inbox_id = inbox.id
     AND inventory.tenant_id = inbox.tenant_id
    WHERE inventory.inbox_id = NEW.inbox_id
      AND inventory.tenant_id = NEW.tenant_id
    FOR SHARE OF inbox, inventory;
    IF inbox_state IS DISTINCT FROM 'claimed' THEN
        RAISE EXCEPTION 'provider delivery workflow inventory entry lacks live authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_inventory_entry_live_authority';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_provider_delivery_workflow_progress() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    inbox_row provider_delivery_inbox%ROWTYPE;
BEGIN
    SELECT inbox_source.* INTO inbox_row
    FROM provider_delivery_inbox AS inbox_source
    JOIN provider_delivery_workflow_inventories AS inventory
      ON inventory.inbox_id = inbox_source.id
     AND inventory.tenant_id = inbox_source.tenant_id
     AND inventory.inventory_digest = NEW.inventory_digest
    WHERE inventory.inbox_id = NEW.inbox_id
      AND inventory.tenant_id = NEW.tenant_id
    FOR SHARE OF inbox_source, inventory;
    IF inbox_row.id IS NULL
        OR inbox_row.state <> 'claimed'
        OR NEW.recorded_at_ms < inbox_row.claimed_at_ms
        OR NEW.recorded_at_ms >= inbox_row.claim_expires_at_ms
    THEN
        RAISE EXCEPTION 'provider delivery workflow progress lacks live authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_progress_live_authority';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_runner_command_payload() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    session_acknowledged BIGINT;
    session_disconnected_at BIGINT;
    session_generation BIGINT;
    session_epoch_value BIGINT;
    current_generation BIGINT;
    current_epoch BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.payload_tombstone_reason IS NOT NULL
            OR NEW.payload_tombstoned_at_ms IS NOT NULL
            OR NEW.envelope_schema IS NULL
            OR NEW.wrapping_key_id IS NULL
            OR NEW.wrapped_data_key IS NULL
            OR NEW.nonce IS NULL
            OR NEW.ciphertext IS NULL
        THEN
            RAISE EXCEPTION 'runner command payloads must be inserted live'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_command_outbox_payload_insert_live';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(
        NEW.runner_session_id, NEW.command_sequence, NEW.operation_id,
        NEW.runner_id, NEW.runner_session_epoch, NEW.runner_generation,
        NEW.command_kind, NEW.command_schema, NEW.command_digest,
        NEW.created_at_ms, NEW.tenant_id, NEW.command_plaintext_size_bytes
    ) IS DISTINCT FROM ROW(
        OLD.runner_session_id, OLD.command_sequence, OLD.operation_id,
        OLD.runner_id, OLD.runner_session_epoch, OLD.runner_generation,
        OLD.command_kind, OLD.command_schema, OLD.command_digest,
        OLD.created_at_ms, OLD.tenant_id, OLD.command_plaintext_size_bytes
    ) THEN
        RAISE EXCEPTION 'runner command authenticated metadata is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_command_outbox_metadata_immutable';
    END IF;

    IF OLD.payload_tombstone_reason IS NOT NULL THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'runner command payload tombstones are immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_command_outbox_tombstone_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.payload_tombstone_reason IS NULL THEN
        IF ROW(
            NEW.envelope_schema, NEW.wrapping_key_id, NEW.wrapped_data_key,
            NEW.nonce, NEW.ciphertext, NEW.payload_tombstoned_at_ms
        ) IS DISTINCT FROM ROW(
            OLD.envelope_schema, OLD.wrapping_key_id, OLD.wrapped_data_key,
            OLD.nonce, OLD.ciphertext, OLD.payload_tombstoned_at_ms
        ) THEN
            RAISE EXCEPTION 'live runner command envelopes are immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_command_outbox_envelope_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.payload_tombstoned_at_ms IS NULL
        OR NEW.envelope_schema IS NOT NULL
        OR NEW.wrapping_key_id IS NOT NULL
        OR NEW.wrapped_data_key IS NOT NULL
        OR NEW.nonce IS NOT NULL
        OR NEW.ciphertext IS NOT NULL
    THEN
        RAISE EXCEPTION 'runner command tombstone must erase the complete envelope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_command_outbox_payload_lifecycle';
    END IF;

    SELECT session.acknowledged_command_sequence,
           session.disconnected_at_ms,
           session.runner_generation,
           session.session_epoch,
           runner.generation,
           runner.session_epoch
    INTO session_acknowledged, session_disconnected_at,
         session_generation, session_epoch_value,
         current_generation, current_epoch
    FROM runner_sessions AS session
    JOIN runners AS runner ON runner.id = session.runner_id
    WHERE session.id = OLD.runner_session_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'runner command session authority is missing'
            USING ERRCODE = 'foreign_key_violation',
                  CONSTRAINT = 'runner_command_outbox_session_fence';
    END IF;

    CASE NEW.payload_tombstone_reason
        WHEN 'acknowledged' THEN
            IF session_disconnected_at IS NOT NULL
                OR (
                    OLD.command_sequence > session_acknowledged
                    AND NOT EXISTS (
                        SELECT 1
                        FROM attempt_cancellation_intents AS cancellation
                        WHERE cancellation.delivery_session_id = OLD.runner_session_id
                          AND cancellation.delivery_command_sequence = OLD.command_sequence
                          AND cancellation.acknowledged_at_ms IS NOT NULL
                          AND cancellation.acknowledged_at_ms <= NEW.payload_tombstoned_at_ms
                    )
                )
            THEN
                RAISE EXCEPTION 'runner command is not acknowledged by a live session'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_command_outbox_ack_tombstone_authority';
            END IF;
        WHEN 'session_closed' THEN
            IF session_disconnected_at IS NULL
                OR NEW.payload_tombstoned_at_ms < session_disconnected_at
                OR session_generation <> current_generation
                OR session_epoch_value <> current_epoch
            THEN
                RAISE EXCEPTION 'runner command session-close tombstone lacks current authority'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_command_outbox_close_tombstone_authority';
            END IF;
        WHEN 'session_superseded' THEN
            IF session_disconnected_at IS NULL
                OR NEW.payload_tombstoned_at_ms < session_disconnected_at
                OR current_generation < session_generation
                OR (
                    current_generation = session_generation
                    AND current_epoch <= session_epoch_value
                )
            THEN
                RAISE EXCEPTION 'runner command supersession tombstone lacks newer authority'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_command_outbox_superseded_tombstone_authority';
            END IF;
        ELSE
            RAISE EXCEPTION 'unknown runner command payload tombstone reason'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_command_outbox_payload_lifecycle';
    END CASE;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_runner_rpc_payload() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    session_disconnected_at BIGINT;
    session_generation BIGINT;
    session_epoch_value BIGINT;
    current_generation BIGINT;
    current_epoch BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.payload_tombstone_reason IS NOT NULL
            OR NEW.payload_tombstoned_at_ms IS NOT NULL
            OR NEW.envelope_schema IS NULL
            OR NEW.wrapping_key_id IS NULL
            OR NEW.wrapped_data_key IS NULL
            OR NEW.nonce IS NULL
            OR NEW.ciphertext IS NULL
        THEN
            RAISE EXCEPTION 'runner RPC payloads must be inserted live'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_rpc_receipts_payload_insert_live';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(
        NEW.runner_session_id, NEW.operation_id, NEW.runner_id,
        NEW.runner_session_epoch, NEW.runner_generation, NEW.operation_kind,
        NEW.request_digest, NEW.response_schema, NEW.response_digest,
        NEW.committed_at_ms, NEW.tenant_id,
        NEW.response_plaintext_size_bytes
    ) IS DISTINCT FROM ROW(
        OLD.runner_session_id, OLD.operation_id, OLD.runner_id,
        OLD.runner_session_epoch, OLD.runner_generation, OLD.operation_kind,
        OLD.request_digest, OLD.response_schema, OLD.response_digest,
        OLD.committed_at_ms, OLD.tenant_id,
        OLD.response_plaintext_size_bytes
    ) THEN
        RAISE EXCEPTION 'runner RPC authenticated metadata is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_rpc_receipts_metadata_immutable';
    END IF;

    IF OLD.payload_tombstone_reason IS NOT NULL THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'runner RPC payload tombstones are immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_rpc_receipts_tombstone_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.payload_tombstone_reason IS NULL THEN
        IF ROW(
            NEW.envelope_schema, NEW.wrapping_key_id, NEW.wrapped_data_key,
            NEW.nonce, NEW.ciphertext, NEW.payload_tombstoned_at_ms
        ) IS DISTINCT FROM ROW(
            OLD.envelope_schema, OLD.wrapping_key_id, OLD.wrapped_data_key,
            OLD.nonce, OLD.ciphertext, OLD.payload_tombstoned_at_ms
        ) THEN
            RAISE EXCEPTION 'live runner RPC envelopes are immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_rpc_receipts_envelope_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.payload_tombstoned_at_ms IS NULL
        OR NEW.envelope_schema IS NOT NULL
        OR NEW.wrapping_key_id IS NOT NULL
        OR NEW.wrapped_data_key IS NOT NULL
        OR NEW.nonce IS NOT NULL
        OR NEW.ciphertext IS NOT NULL
    THEN
        RAISE EXCEPTION 'runner RPC tombstone must erase the complete envelope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_rpc_receipts_payload_lifecycle';
    END IF;

    SELECT session.disconnected_at_ms,
           session.runner_generation,
           session.session_epoch,
           runner.generation,
           runner.session_epoch
    INTO session_disconnected_at, session_generation, session_epoch_value,
         current_generation, current_epoch
    FROM runner_sessions AS session
    JOIN runners AS runner ON runner.id = session.runner_id
    WHERE session.id = OLD.runner_session_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'runner RPC session authority is missing'
            USING ERRCODE = 'foreign_key_violation',
                  CONSTRAINT = 'runner_rpc_receipts_session_fence';
    END IF;

    CASE NEW.payload_tombstone_reason
        WHEN 'session_closed' THEN
            IF session_disconnected_at IS NULL
                OR NEW.payload_tombstoned_at_ms < session_disconnected_at
                OR session_generation <> current_generation
                OR session_epoch_value <> current_epoch
            THEN
                RAISE EXCEPTION 'runner RPC session-close tombstone lacks current authority'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_rpc_receipts_close_tombstone_authority';
            END IF;
        WHEN 'session_superseded' THEN
            IF session_disconnected_at IS NULL
                OR NEW.payload_tombstoned_at_ms < session_disconnected_at
                OR current_generation < session_generation
                OR (
                    current_generation = session_generation
                    AND current_epoch <= session_epoch_value
                )
            THEN
                RAISE EXCEPTION 'runner RPC supersession tombstone lacks newer authority'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_rpc_receipts_superseded_tombstone_authority';
            END IF;
        ELSE
            RAISE EXCEPTION 'unknown runner RPC payload tombstone reason'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_rpc_receipts_payload_lifecycle';
    END CASE;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_logical_workflow_invocation_run_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.invocation_kind = 'reusable'
       AND OLD.state = 'active'
       AND NEW.state IN ('completed', 'cancelled', 'failed')
       AND NEW.revision = OLD.revision + 1
       AND NEW.updated_at_ms >= OLD.updated_at_ms
       AND EXISTS (
           SELECT 1
           FROM logical_workflow_reusable_call_results AS call_result
           JOIN logical_workflow_reusable_call_publications AS publication
             ON publication.run_id = call_result.run_id
            AND publication.parent_invocation_id =
                call_result.parent_invocation_id
            AND publication.caller_logical_job_id =
                call_result.caller_logical_job_id
           WHERE call_result.run_id = NEW.run_id
             AND call_result.child_invocation_id = NEW.id
             AND call_result.sealed_at_ms IS NOT NULL
             AND publication.condition_matched
             AND call_result.completed_at_ms = NEW.updated_at_ms
             AND NEW.state = CASE call_result.effective_conclusion
                 WHEN 'success' THEN 'completed'
                 WHEN 'skipped' THEN 'completed'
                 WHEN 'cancelled' THEN 'cancelled'
                 ELSE 'failed'
             END
       )
    THEN
        RETURN NEW;
    END IF;

    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state = 'cancelled'
       AND OLD.state IN ('pending', 'active')
       AND NEW.revision = OLD.revision + 1
       AND NEW.updated_at_ms >= OLD.updated_at_ms
       AND EXISTS (
           SELECT 1
           FROM logical_workflow_concurrency_cancellations AS cancellation
           WHERE cancellation.run_id = NEW.run_id
             AND cancellation.root_invocation_id = NEW.id
             AND cancellation.prior_invocation_state = OLD.state
             AND cancellation.prior_invocation_revision = OLD.revision
             AND cancellation.prior_invocation_updated_at_ms = OLD.updated_at_ms
             AND cancellation.cancelled_at_ms = NEW.updated_at_ms
       )
    THEN
        RETURN NEW;
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state IN ('completed', 'cancelled', 'failed') THEN
        IF OLD.state NOT IN ('pending', 'active')
           OR NEW.revision <> OLD.revision + 1
           OR NEW.updated_at_ms < OLD.updated_at_ms
           OR NOT EXISTS (
               SELECT 1
               FROM logical_workflow_run_results AS run_result
               JOIN logical_workflow_run_result_claims AS claim
                 ON claim.run_id = run_result.run_id
               WHERE run_result.run_id = NEW.run_id
                 AND run_result.root_invocation_id = NEW.id
                 AND claim.state = 'aggregating'
                 AND run_result.invocation_state = OLD.state
                 AND run_result.invocation_revision = OLD.revision
                 AND run_result.invocation_updated_at_ms = OLD.updated_at_ms
                 AND run_result.finalized_at_ms = NEW.updated_at_ms
                 AND NEW.state = CASE run_result.effective_conclusion
                     WHEN 'success' THEN 'completed'
                     WHEN 'skipped' THEN 'completed'
                     WHEN 'cancelled' THEN 'cancelled'
                     ELSE 'failed'
                 END
           )
        THEN
            RAISE EXCEPTION 'logical workflow invocation terminal transition lacks result evidence'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state IN ('completed', 'cancelled', 'failed')
          AND (NEW.state IS DISTINCT FROM OLD.state
               OR NEW.revision IS DISTINCT FROM OLD.revision
               OR NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms) THEN
        RAISE EXCEPTION 'logical workflow terminal invocation is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_logical_workflow_marker_run_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state = 'cancelled'
       AND OLD.state IN ('pending', 'active')
       AND NEW.revision = OLD.revision + 1
       AND NEW.updated_at_ms >= OLD.updated_at_ms
       AND EXISTS (
           SELECT 1
           FROM logical_workflow_concurrency_cancellations AS cancellation
           WHERE cancellation.run_id = NEW.run_id
             AND cancellation.root_invocation_id = NEW.root_invocation_id
             AND cancellation.prior_marker_state = OLD.state
             AND cancellation.prior_marker_revision = OLD.revision
             AND cancellation.prior_marker_updated_at_ms = OLD.updated_at_ms
             AND cancellation.cancelled_at_ms = NEW.updated_at_ms
       )
    THEN
        RETURN NEW;
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state IN ('completed', 'cancelled', 'failed') THEN
        IF OLD.state NOT IN ('pending', 'active')
           OR NEW.revision <> OLD.revision + 1
           OR NEW.updated_at_ms < OLD.updated_at_ms
           OR NOT EXISTS (
               SELECT 1
               FROM logical_workflow_run_results AS result
               JOIN logical_workflow_run_result_claims AS claim
                 ON claim.run_id = result.run_id
               WHERE result.run_id = NEW.run_id
                 AND claim.state = 'aggregating'
                 AND result.marker_state = OLD.state
                 AND result.marker_revision = OLD.revision
                 AND result.marker_updated_at_ms = OLD.updated_at_ms
                 AND result.finalized_at_ms = NEW.updated_at_ms
                 AND NEW.state = CASE result.effective_conclusion
                     WHEN 'success' THEN 'completed'
                     WHEN 'skipped' THEN 'completed'
                     WHEN 'cancelled' THEN 'cancelled'
                     ELSE 'failed'
                 END
           )
        THEN
            RAISE EXCEPTION 'logical workflow marker terminal transition lacks run result'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state IN ('completed', 'cancelled', 'failed')
          AND (NEW.state IS DISTINCT FROM OLD.state
               OR NEW.revision IS DISTINCT FROM OLD.revision
               OR NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms) THEN
        RAISE EXCEPTION 'logical workflow terminal marker is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_workflow_run_plan_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.status IN ('queued', 'in_progress')
       AND NEW.status = 'cancelled'
       AND EXISTS (
           SELECT 1 FROM logical_workflow_runs AS marker
           WHERE marker.run_id = OLD.id
       )
    THEN
        IF NOT EXISTS (
            SELECT 1
            FROM logical_workflow_concurrency_cancellations AS cancellation
            WHERE cancellation.run_id = OLD.id
              AND cancellation.prior_workflow_status = OLD.status
              AND cancellation.prior_workflow_updated_at_ms = OLD.updated_at_ms
              AND cancellation.cancelled_at_ms = NEW.updated_at_ms
        ) THEN
            RAISE EXCEPTION 'logical workflow cancellation lacks concurrency evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.status IS DISTINCT FROM OLD.status
        OR (OLD.status = 'cancelled'
            AND NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms))
       AND EXISTS (
           SELECT 1 FROM logical_workflow_runs AS marker
           WHERE marker.run_id = OLD.id
       )
       AND (
           NEW.status = 'completed'
           OR (OLD.status = 'cancelled'
              AND NEW.status = 'cancelled'
              AND NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms)
           OR EXISTS (
               SELECT 1
               FROM logical_workflow_run_result_claims AS claim
               WHERE claim.run_id = OLD.id AND claim.state = 'aggregating'
           )
       )
    THEN
        IF OLD.status NOT IN ('queued', 'in_progress', 'cancelled')
           OR NEW.updated_at_ms < OLD.updated_at_ms
           OR NOT EXISTS (
               SELECT 1
               FROM logical_workflow_run_results AS result
               JOIN logical_workflow_run_result_claims AS claim
                 ON claim.run_id = result.run_id
               WHERE result.run_id = OLD.id
                 AND claim.state = 'aggregating'
                 AND result.workflow_status = OLD.status
                 AND result.workflow_updated_at_ms = OLD.updated_at_ms
                 AND result.finalized_at_ms = NEW.updated_at_ms
                 AND NEW.status = CASE result.effective_conclusion
                     WHEN 'cancelled' THEN 'cancelled'
                     ELSE 'completed'
                 END
           )
        THEN
            RAISE EXCEPTION 'logical workflow workflow status transition lacks run result'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_is_canonical_logical_activation_workspace(workspace text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE STRICT
    AS $$
DECLARE
    component TEXT;
    components TEXT[];
BEGIN
    IF octet_length(workspace) NOT BETWEEN 2 AND 1024
        OR workspace ~ '[[:cntrl:]]'
        OR btrim(workspace) <> workspace
    THEN
        RETURN FALSE;
    END IF;

    IF left(workspace, 1) = '/' THEN
        IF workspace = '/' OR position('//' IN workspace) > 0 THEN
            RETURN FALSE;
        END IF;
        components := string_to_array(substring(workspace FROM 2), '/');
    ELSIF workspace ~ E'^[A-Za-z]:\\\\' THEN
        IF position('/' IN workspace) > 0
            OR position(E'\\\\\\\\' IN workspace) > 0
        THEN
            RETURN FALSE;
        END IF;
        components := string_to_array(substring(workspace FROM 4), E'\\');
    ELSE
        RETURN FALSE;
    END IF;

    FOREACH component IN ARRAY components LOOP
        IF component = '' OR component = '.' OR component = '..' THEN
            RETURN FALSE;
        END IF;
    END LOOP;
    RETURN TRUE;
END;
$$;

CREATE FUNCTION automata_job_attempt_output_safety_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.secret_exposure_class IS DISTINCT FROM OLD.secret_exposure_class
       OR NEW.raw_log_disposition IS DISTINCT FROM OLD.raw_log_disposition
       OR NEW.requested_log_visibility IS DISTINCT FROM OLD.requested_log_visibility
       OR NEW.effective_log_visibility IS DISTINCT FROM OLD.effective_log_visibility
       OR NEW.output_safety_reason IS DISTINCT FROM OLD.output_safety_reason
       OR NEW.output_safety_schema IS DISTINCT FROM OLD.output_safety_schema
       OR NEW.classified_at_ms IS DISTINCT FROM OLD.classified_at_ms THEN
        RAISE EXCEPTION 'job attempt output safety snapshots are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'job_attempts_output_safety_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_job_attempt_started_at_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.lease_issued_at_ms IS NOT NULL THEN
            IF NEW.started_at_ms IS NULL THEN
                NEW.started_at_ms := NEW.lease_issued_at_ms;
            ELSIF NEW.started_at_ms <> NEW.lease_issued_at_ms THEN
                RAISE EXCEPTION 'job attempt start must equal its first lease issuance'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'job_attempts_started_at_immutable';
            END IF;
        ELSIF NEW.started_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'job attempt start requires an issued lease'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'job_attempts_started_at_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.started_at_ms IS NOT NULL THEN
        IF NEW.started_at_ms IS DISTINCT FROM OLD.started_at_ms THEN
            RAISE EXCEPTION 'job attempt start is immutable'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'job_attempts_started_at_immutable';
        END IF;
    ELSIF NEW.lease_issued_at_ms IS NOT NULL THEN
        IF NEW.started_at_ms IS NULL THEN
            NEW.started_at_ms := NEW.lease_issued_at_ms;
        ELSIF NEW.started_at_ms <> NEW.lease_issued_at_ms THEN
            RAISE EXCEPTION 'job attempt start must equal its first lease issuance'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'job_attempts_started_at_immutable';
        END IF;
    ELSIF NEW.started_at_ms IS NOT NULL THEN
        RAISE EXCEPTION 'job attempt start requires an issued lease'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'job_attempts_started_at_immutable';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_job_attempt_terminal_monotonic() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.lifecycle IN (
        'succeeded', 'failed', 'cancelled', 'timed_out', 'skipped', 'lost'
    ) AND NEW.lifecycle IS DISTINCT FROM OLD.lifecycle THEN
        RAISE EXCEPTION 'terminal job attempts are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'job_attempts_terminal_monotonic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_job_binding_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'job credential bindings are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'job_credential_bindings_append_only';
END;
$$;

CREATE FUNCTION automata_job_credential_resolution_digest(target_attempt_id uuid) RETURNS bytea
    LANGUAGE sql STABLE
    AS $_$
SELECT pg_catalog.sha256(
    convert_to('automata.store.job-credential-resolution.v2', 'UTF8')
    || decode('00', 'hex')
    || uuid_send($1)
    || convert_to(jsonb_build_object(
        'secrets', COALESCE((
            SELECT jsonb_agg(jsonb_build_array(canonical_name, encode(binding_digest, 'hex'))
                             ORDER BY canonical_name)
            FROM job_secret_selections WHERE attempt_id = $1
        ), '[]'::JSONB),
        'missing_secrets', COALESCE((
            SELECT jsonb_agg(canonical_name ORDER BY canonical_name)
            FROM job_missing_secret_bindings WHERE attempt_id = $1
        ), '[]'::JSONB),
        'variables', COALESCE((
            SELECT jsonb_agg(jsonb_build_array(canonical_name, encode(binding_digest, 'hex'))
                             ORDER BY canonical_name)
            FROM job_variable_bindings WHERE attempt_id = $1
        ), '[]'::JSONB),
        'missing_variables', COALESCE((
            SELECT jsonb_agg(canonical_name ORDER BY canonical_name)
            FROM job_missing_variable_bindings WHERE attempt_id = $1
        ), '[]'::JSONB)
    )::TEXT, 'UTF8')
);
$_$;

CREATE FUNCTION automata_job_environment_gate_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    environment repository_environments%ROWTYPE;
    approval protected_environment_approval_requests%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
       OR NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
       OR NEW.instance_id IS DISTINCT FROM OLD.instance_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.environment_requirement_kind IS DISTINCT FROM OLD.environment_requirement_kind
       OR NEW.environment_template_digest IS DISTINCT FROM OLD.environment_template_digest
       OR NEW.invocation_kind IS DISTINCT FROM OLD.invocation_kind
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'job environment gate identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'job_environment_gates_identity_immutable';
    END IF;
    IF NOT (
        (OLD.state = 'unclassified' AND NEW.state = 'unclassified')
        OR (OLD.state = 'selection_pending'
            AND NEW.state IN ('selection_pending', 'waiting', 'resolving', 'cancelled'))
        OR (OLD.state = 'waiting'
            AND NEW.state IN ('waiting', 'resolving', 'rejected', 'expired', 'cancelled'))
        OR (OLD.state = 'resolving'
            AND NEW.state IN ('resolving', 'ready', 'expired', 'cancelled'))
        OR (OLD.state IN ('ready', 'rejected', 'expired', 'cancelled')
            AND NEW.state = OLD.state)
    ) THEN
        RAISE EXCEPTION 'job environment gate transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'job_environment_gates_state_transition';
    END IF;
    IF OLD.state <> 'selection_pending' AND (
        NEW.environment_id IS DISTINCT FROM OLD.environment_id
        OR NEW.environment_revision IS DISTINCT FROM OLD.environment_revision
        OR NEW.approval_request_id IS DISTINCT FROM OLD.approval_request_id
        OR NEW.event_trust IS DISTINCT FROM OLD.event_trust
        OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
        OR NEW.reusable_secret_permission IS DISTINCT FROM OLD.reusable_secret_permission
    ) THEN
        RAISE EXCEPTION 'job environment selection evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'job_environment_gates_selection_immutable';
    END IF;
    IF NEW.state IN ('waiting', 'resolving', 'ready')
       AND NEW.environment_id IS NOT NULL THEN
        SELECT * INTO STRICT environment
        FROM repository_environments
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND id = NEW.environment_id
        FOR SHARE;
        IF environment.status <> 'active'
           OR environment.revision <> NEW.environment_revision THEN
            RAISE EXCEPTION 'job environment selection is stale'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_environment_gates_environment_current';
        END IF;
        IF NEW.state = 'waiting' THEN
            IF environment.protection_mode <> 'required_approvals'
               OR NEW.approval_request_id IS NULL THEN
                RAISE EXCEPTION 'waiting gate requires a protected environment request'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'job_environment_gates_waiting_approval';
            END IF;
            SELECT * INTO STRICT approval
            FROM protected_environment_approval_requests
            WHERE tenant_id = NEW.tenant_id AND id = NEW.approval_request_id
            FOR SHARE;
            IF approval.status <> 'pending'
               OR approval.environment_revision <> environment.revision
               OR approval.required_approvals <> environment.required_approvals
               OR approval.prevent_self_review <> environment.prevent_self_review
               OR database_now_ms >= approval.expires_at_ms THEN
                RAISE EXCEPTION 'waiting gate approval request is stale'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'job_environment_gates_waiting_approval';
            END IF;
        ELSIF environment.protection_mode = 'required_approvals' THEN
            SELECT * INTO STRICT approval
            FROM protected_environment_approval_requests
            WHERE tenant_id = NEW.tenant_id AND id = NEW.approval_request_id
            FOR SHARE;
            IF approval.status <> 'approved'
               OR approval.environment_revision <> environment.revision
               OR approval.required_approvals <> environment.required_approvals
               OR approval.prevent_self_review <> environment.prevent_self_review
               OR approval.resolved_at_ms IS NULL
               OR approval.resolved_at_ms >= approval.expires_at_ms
               OR database_now_ms >= approval.expires_at_ms
               OR NOT automata_protected_environment_approval_is_current(
                   NEW.tenant_id, NEW.approval_request_id, database_now_ms
               ) THEN
                RAISE EXCEPTION 'protected environment gate lacks current approval'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'job_environment_gates_approved_current';
            END IF;
        ELSIF NEW.approval_request_id IS NOT NULL THEN
            RAISE EXCEPTION 'unprotected environment cannot retain approval evidence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_environment_gates_approved_current';
        END IF;
    END IF;
    IF OLD.state IN ('ready', 'rejected', 'expired', 'cancelled')
       AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal job environment gate is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'job_environment_gates_terminal_monotonic';
    END IF;
    IF NEW IS DISTINCT FROM OLD AND NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'job environment gate transition requires one revision increment'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'job_environment_gates_revision_guard';
    END IF;
    IF NEW.state = 'ready' THEN
        IF NEW.resolution_digest IS DISTINCT FROM
               automata_job_credential_resolution_digest(NEW.attempt_id)
           OR NEW.resolved_secret_count <> (
               SELECT count(*) FROM job_secret_selections WHERE attempt_id = NEW.attempt_id
           )
           OR NEW.missing_secret_count <> (
               SELECT count(*) FROM job_missing_secret_bindings WHERE attempt_id = NEW.attempt_id
           )
           OR NEW.resolved_variable_count <> (
               SELECT count(*) FROM job_variable_bindings WHERE attempt_id = NEW.attempt_id
           )
           OR NEW.missing_variable_count <> (
               SELECT count(*) FROM job_missing_variable_bindings WHERE attempt_id = NEW.attempt_id
           ) THEN
            RAISE EXCEPTION 'job credential resolution digest is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'job_environment_gates_resolution_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_job_environment_gate_ready_authority_is_current(target_attempt_id uuid, target_now_ms bigint) RETURNS boolean
    LANGUAGE sql STABLE
    AS $_$
SELECT EXISTS (
    SELECT 1
    FROM job_environment_gates AS gate
    JOIN logical_workflow_jobs AS logical_job
      ON logical_job.run_id = gate.run_id
     AND logical_job.invocation_id = gate.invocation_id
     AND logical_job.id = gate.logical_job_id
    WHERE gate.attempt_id = $1
      AND gate.state = 'ready'
      AND gate.environment_requirement_kind =
          logical_job.environment_requirement_kind
      AND gate.environment_template_digest IS NOT DISTINCT FROM
          logical_job.environment_template_digest
      AND gate.resolution_digest IS NOT DISTINCT FROM
          automata_job_credential_resolution_digest(gate.attempt_id)
      AND NOT (
          gate.event_trust = 'unknown'
          AND cardinality(logical_job.secret_reference_names) > 0
      )
      AND NOT (
          gate.source_kind = 'unknown'
          AND cardinality(logical_job.secret_reference_names) > 0
      )
      AND NOT (
          gate.invocation_kind = 'reusable'
          AND cardinality(logical_job.secret_reference_names) > 0
          AND gate.reusable_secret_permission <> 'explicit'
      )
      AND (
          (gate.environment_id IS NULL
           AND gate.environment_revision IS NULL
           AND gate.approval_request_id IS NULL)
          OR EXISTS (
              SELECT 1
              FROM repository_environments AS environment
              WHERE environment.tenant_id = gate.tenant_id
                AND environment.repository_id = gate.repository_id
                AND environment.id = gate.environment_id
                AND environment.status = 'active'
                AND environment.revision = gate.environment_revision
                AND (
                    (environment.protection_mode = 'unprotected'
                     AND gate.approval_request_id IS NULL)
                    OR (
                        environment.protection_mode = 'required_approvals'
                        AND gate.approval_request_id IS NOT NULL
                        AND automata_protected_environment_approval_is_current(
                            gate.tenant_id,
                            gate.approval_request_id,
                            $2
                        )
                    )
                )
          )
      )
      AND gate.resolved_secret_count = (
          SELECT count(*)
          FROM job_secret_selections AS selection
          JOIN secrets AS secret
            ON secret.tenant_id = selection.tenant_id
           AND secret.id = selection.secret_id
           AND secret.current_version_id = selection.secret_version_id
           AND secret.current_version_number = selection.secret_version_number
           AND secret.canonical_name = selection.canonical_name
           AND secret.scope_kind = selection.scope_kind
           AND secret.environment_id IS NOT DISTINCT FROM selection.environment_id
          JOIN secret_policies AS policy
            ON policy.tenant_id = secret.tenant_id
           AND policy.secret_id = secret.id
          WHERE selection.attempt_id = gate.attempt_id
            AND selection.tenant_id = gate.tenant_id
            AND selection.binding_digest IS NOT DISTINCT FROM
                automata_job_secret_selection_digest(
                    selection.attempt_id,
                    selection.canonical_name,
                    selection.tenant_id,
                    selection.secret_id,
                    selection.secret_version_id,
                    selection.secret_version_number,
                    selection.scope_kind,
                    selection.environment_id
                )
            AND automata_secret_is_available_to_gate(secret, policy, gate)
            AND NOT (
                selection.scope_kind = 'repository'
                AND EXISTS (
                    SELECT 1
                    FROM secrets AS higher
                    JOIN secret_policies AS higher_policy
                      ON higher_policy.tenant_id = higher.tenant_id
                     AND higher_policy.secret_id = higher.id
                    WHERE higher.tenant_id = gate.tenant_id
                      AND higher.repository_id = gate.repository_id
                      AND higher.environment_id = gate.environment_id
                      AND higher.scope_kind = 'environment'
                      AND higher.canonical_name = selection.canonical_name
                      AND automata_secret_is_available_to_gate(
                          higher,
                          higher_policy,
                          gate
                      )
                )
            )
            AND NOT (
                selection.scope_kind = 'tenant'
                AND EXISTS (
                    SELECT 1
                    FROM secrets AS higher
                    JOIN secret_policies AS higher_policy
                      ON higher_policy.tenant_id = higher.tenant_id
                     AND higher_policy.secret_id = higher.id
                    WHERE higher.tenant_id = gate.tenant_id
                      AND higher.repository_id = gate.repository_id
                      AND higher.canonical_name = selection.canonical_name
                      AND higher.scope_kind IN ('repository', 'environment')
                      AND (
                          higher.scope_kind = 'repository'
                          OR higher.environment_id = gate.environment_id
                      )
                      AND automata_secret_is_available_to_gate(
                          higher,
                          higher_policy,
                          gate
                      )
                )
            )
      )
      AND gate.resolved_variable_count = (
          SELECT count(*)
          FROM job_variable_bindings AS binding
          JOIN workflow_variables AS variable
            ON variable.tenant_id = binding.tenant_id
           AND variable.id = binding.variable_id
           AND variable.repository_id = gate.repository_id
           AND variable.canonical_name = binding.canonical_name
           AND variable.scope_kind = binding.scope_kind
           AND variable.environment_id IS NOT DISTINCT FROM binding.environment_id
           AND variable.current_version_id = binding.variable_version_id
           AND variable.current_version_number = binding.variable_version_number
           AND variable.status = 'active'
          WHERE binding.attempt_id = gate.attempt_id
            AND binding.tenant_id = gate.tenant_id
            AND binding.binding_digest IS NOT DISTINCT FROM
                automata_job_variable_binding_digest(
                    binding.attempt_id,
                    binding.canonical_name,
                    binding.tenant_id,
                    binding.variable_id,
                    binding.variable_version_id,
                    binding.variable_version_number,
                    binding.scope_kind,
                    binding.environment_id
                )
            AND (
                binding.scope_kind = 'repository'
                OR binding.environment_id = gate.environment_id
            )
            AND NOT EXISTS (
                SELECT 1
                FROM workflow_variables AS higher
                WHERE higher.tenant_id = gate.tenant_id
                  AND higher.repository_id = gate.repository_id
                  AND higher.environment_id = gate.environment_id
                  AND higher.scope_kind = 'environment'
                  AND higher.canonical_name = binding.canonical_name
                  AND higher.status = 'active'
                  AND binding.scope_kind = 'repository'
            )
      )
      AND gate.missing_secret_count = (
          SELECT count(*)
          FROM job_missing_secret_bindings
          WHERE attempt_id = gate.attempt_id
      )
      AND gate.missing_variable_count = (
          SELECT count(*)
          FROM job_missing_variable_bindings
          WHERE attempt_id = gate.attempt_id
      )
      AND gate.resolved_secret_count + gate.missing_secret_count =
          cardinality(logical_job.secret_reference_names)
      AND gate.resolved_variable_count + gate.missing_variable_count =
          cardinality(logical_job.variable_reference_names)
);
$_$;
