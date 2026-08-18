-- EVT-01: persist the canonical event envelope accepted with each provider delivery.
--
-- Every row carries one complete, bounded envelope. This is a greenfield
-- canonical schema; unsealed provider deliveries are not representable.

ALTER TABLE provider_delivery_inbox
    ADD COLUMN event_envelope_schema SMALLINT NOT NULL,
    ADD COLUMN event_registry_schema SMALLINT NOT NULL,
    ADD COLUMN event_envelope_digest BYTEA NOT NULL,
    ADD COLUMN event_envelope_bytes BYTEA NOT NULL,
    ADD COLUMN event_envelope_media_type TEXT COLLATE "C" NOT NULL;

ALTER TABLE provider_delivery_inbox
    ADD CONSTRAINT provider_delivery_inbox_event_envelope_complete CHECK (
        event_envelope_schema > 0
        AND event_registry_schema > 0
        AND octet_length(event_envelope_digest) = 32
        AND octet_length(event_envelope_bytes) BETWEEN 1 AND 32768
        AND octet_length(event_envelope_media_type) BETWEEN 1 AND 128
        AND event_envelope_media_type LIKE '%/%'
        AND event_envelope_media_type ~ '^[!-~]+$'
        AND event_envelope_media_type !~ '[[:space:][:cntrl:];]'
    );

-- Envelope evidence is immutable after acceptance; the original state machine
-- remains closed over canonical sealed deliveries.
CREATE OR REPLACE FUNCTION automata_enforce_provider_delivery_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.provider IS DISTINCT FROM OLD.provider
        OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
        OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
        OR NEW.provider_repository_id IS DISTINCT FROM OLD.provider_repository_id
        OR NEW.repository_visibility IS DISTINCT FROM OLD.repository_visibility
        OR NEW.repository_identity IS DISTINCT FROM OLD.repository_identity
        OR NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
        OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
        OR NEW.raw_event_digest IS DISTINCT FROM OLD.raw_event_digest
        OR NEW.raw_event_object_key IS DISTINCT FROM OLD.raw_event_object_key
        OR NEW.raw_event_size_bytes IS DISTINCT FROM OLD.raw_event_size_bytes
        OR NEW.raw_event_media_type IS DISTINCT FROM OLD.raw_event_media_type
        OR NEW.event_envelope_schema IS DISTINCT FROM OLD.event_envelope_schema
        OR NEW.event_registry_schema IS DISTINCT FROM OLD.event_registry_schema
        OR NEW.event_envelope_digest IS DISTINCT FROM OLD.event_envelope_digest
        OR NEW.event_envelope_bytes IS DISTINCT FROM OLD.event_envelope_bytes
        OR NEW.event_envelope_media_type IS DISTINCT FROM OLD.event_envelope_media_type
        OR NEW.accepted_at_ms IS DISTINCT FROM OLD.accepted_at_ms
    THEN
        RAISE EXCEPTION 'provider delivery immutable evidence cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_inbox_evidence_immutable';
    END IF;

    IF NEW.state_updated_at_ms < OLD.state_updated_at_ms THEN
        RAISE EXCEPTION 'provider delivery state time cannot regress'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_inbox_time_regression';
    END IF;

    IF OLD.state IN ('pending', 'retry') AND NEW.state = 'claimed' THEN
        IF NEW.claim_fence <> OLD.claim_fence + 1
            OR NEW.attempt_count <> OLD.attempt_count + 1
            OR NEW.claimed_at_ms < OLD.state_updated_at_ms
            OR NEW.state_updated_at_ms IS DISTINCT FROM NEW.claimed_at_ms
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
            OR (
                OLD.state = 'retry'
                AND NEW.claimed_at_ms < OLD.next_attempt_at_ms
            )
            OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
        THEN
            RAISE EXCEPTION 'provider delivery claim must advance exact retry state'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_claim_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'claimed' THEN
        IF NEW.claim_fence = OLD.claim_fence + 1
            AND NEW.claimed_at_ms IS NOT DISTINCT FROM OLD.claimed_at_ms
        THEN
            IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                OR NEW.claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
                OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
                OR NEW.claim_expires_at_ms <= OLD.claim_expires_at_ms
                OR NEW.state_updated_at_ms <= OLD.state_updated_at_ms
                OR NEW.state_updated_at_ms >= OLD.claim_expires_at_ms
                OR NEW.renewal_predecessor_expires_at_ms
                    IS DISTINCT FROM OLD.claim_expires_at_ms
            THEN
                RAISE EXCEPTION 'provider delivery renewal must rotate and strictly extend the live exact claim'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'provider_delivery_inbox_renewal_transition';
            END IF;
        ELSIF NEW.claim_fence = OLD.claim_fence + 1 THEN
            IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                OR NEW.claimed_at_ms < OLD.claim_expires_at_ms
                OR NEW.state_updated_at_ms IS DISTINCT FROM NEW.claimed_at_ms
                OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
                OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
            THEN
                RAISE EXCEPTION 'provider delivery crash reclaim must advance only its fence'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'provider_delivery_inbox_reclaim_transition';
            END IF;
        ELSE
            RAISE EXCEPTION 'provider delivery claimed-state transition has an invalid fence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_claimed_fence_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'retry' THEN
        IF NEW.claim_fence <> OLD.claim_fence
            OR NEW.attempt_count <> OLD.attempt_count
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
        THEN
            RAISE EXCEPTION 'provider delivery retry must close the exact claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_retry_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'completed' THEN
        IF NEW.claim_fence <> OLD.claim_fence
            OR NEW.attempt_count <> OLD.attempt_count
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
            OR NEW.terminal_claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
            OR NEW.terminal_claim_fence IS DISTINCT FROM OLD.claim_fence
        THEN
            RAISE EXCEPTION 'provider delivery completion must close the exact claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_completion_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'rejected' THEN
        IF NEW.claim_fence <> OLD.claim_fence
            OR NEW.attempt_count <> OLD.attempt_count
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
            OR NEW.terminal_claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
            OR NEW.terminal_claim_fence IS DISTINCT FROM OLD.claim_fence
        THEN
            RAISE EXCEPTION 'provider delivery rejection must close the exact claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_rejection_transition';
        END IF;
    ELSE
        RAISE EXCEPTION 'provider delivery lifecycle transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_inbox_lifecycle_transition';
    END IF;
    RETURN NEW;
END;
$$;
