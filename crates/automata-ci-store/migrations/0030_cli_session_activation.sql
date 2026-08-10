-- CLI bearer delivery is a two-phase contract. A finalized device sign-in
-- commits only a short-lived, unusable pending session. The client activates
-- that exact lookup only after encrypted local credential custody succeeds.
--
-- This is a current-only pre-release schema. Guessing lifecycle state for rows
-- created under the older contract could make an unknown bearer usable, so an
-- occupied human-session table must be deliberately cleared before migration.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM human_sessions LIMIT 1) THEN
        RAISE EXCEPTION
            '0030_cli_session_activation requires an empty human_sessions table'
            USING ERRCODE = '23514';
    END IF;
END
$$;

ALTER TABLE human_sessions
    ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN activation_deadline_ms BIGINT,
    ADD COLUMN activated_at_ms BIGINT,
    ADD CONSTRAINT human_sessions_activation_shape CHECK ((
        (
            session_kind = 'browser'
            AND audience = 'automata.web'
            AND lifecycle_status = 'active'
            AND activation_deadline_ms IS NULL
            AND activated_at_ms IS NULL
        ) OR (
            session_kind = 'cli'
            AND audience = 'automata.cli'
            AND lifecycle_status = 'pending_activation'
            AND issued_at_ms >= 0
            AND activation_deadline_ms > issued_at_ms
            AND activation_deadline_ms <= expires_at_ms
            AND activation_deadline_ms - issued_at_ms BETWEEN 1 AND 300000
            AND activated_at_ms IS NULL
        ) OR (
            session_kind = 'cli'
            AND audience = 'automata.cli'
            AND lifecycle_status = 'active'
            AND issued_at_ms >= 0
            AND activation_deadline_ms > issued_at_ms
            AND activation_deadline_ms <= expires_at_ms
            AND activation_deadline_ms - issued_at_ms BETWEEN 1 AND 300000
            AND activated_at_ms >= issued_at_ms
            AND activated_at_ms < activation_deadline_ms
        )
    ) IS TRUE);

CREATE FUNCTION guard_human_session_activation_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.session_kind = 'browser' THEN
            IF NEW.lifecycle_status <> 'active'
               OR NEW.activation_deadline_ms IS NOT NULL
               OR NEW.activated_at_ms IS NOT NULL THEN
                RAISE EXCEPTION 'browser sessions are immediately active'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.session_kind = 'cli' THEN
            IF NEW.lifecycle_status <> 'pending_activation'
               OR NEW.activation_deadline_ms IS NULL
               OR NEW.activated_at_ms IS NOT NULL THEN
                RAISE EXCEPTION 'new CLI sessions must await activation'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.session_kind IS DISTINCT FROM OLD.session_kind
       OR NEW.audience IS DISTINCT FROM OLD.audience
       OR NEW.issued_at_ms IS DISTINCT FROM OLD.issued_at_ms
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
       OR NEW.activation_deadline_ms IS DISTINCT FROM OLD.activation_deadline_ms THEN
        RAISE EXCEPTION 'session activation identity and deadline are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.lifecycle_status = 'pending_activation'
       AND NEW.lifecycle_status = 'active' THEN
        IF OLD.session_kind <> 'cli'
           OR OLD.audience <> 'automata.cli'
           OR OLD.activated_at_ms IS NOT NULL
           OR NEW.activated_at_ms IS NULL
           OR NEW.activated_at_ms < OLD.issued_at_ms
           OR NEW.activated_at_ms >= OLD.activation_deadline_ms
           OR NEW.revision <> OLD.revision + 1 THEN
            RAISE EXCEPTION 'invalid CLI session activation transition'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.lifecycle_status IS DISTINCT FROM OLD.lifecycle_status
       OR NEW.activated_at_ms IS DISTINCT FROM OLD.activated_at_ms THEN
        RAISE EXCEPTION 'session activation lifecycle is monotonic'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER human_sessions_activation_lifecycle_guard
BEFORE INSERT OR UPDATE OF
    session_kind,
    audience,
    lifecycle_status,
    activation_deadline_ms,
    activated_at_ms,
    issued_at_ms,
    expires_at_ms,
    revision
ON human_sessions
FOR EACH ROW
EXECUTE FUNCTION guard_human_session_activation_lifecycle();

DROP INDEX human_sessions_active_token_lookup;

CREATE INDEX human_sessions_active_token_lookup
    ON human_sessions (token_hash_key_id, token_hash, expires_at_ms)
    WHERE revoked_at_ms IS NULL AND lifecycle_status = 'active';

CREATE INDEX human_sessions_pending_activation_expiry
    ON human_sessions (activation_deadline_ms, id)
    WHERE lifecycle_status = 'pending_activation' AND revoked_at_ms IS NULL;
