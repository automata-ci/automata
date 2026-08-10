-- Preserve the first concrete execution start independently from mutable
-- lease custody. Historical terminal attempts whose lease was already cleared
-- remain honestly unknown.

LOCK TABLE job_attempts IN ACCESS EXCLUSIVE MODE;

ALTER TABLE job_attempts
    ADD COLUMN started_at_ms BIGINT;

UPDATE job_attempts
SET started_at_ms = lease_issued_at_ms
WHERE lease_issued_at_ms IS NOT NULL;

ALTER TABLE job_attempts
    ADD CONSTRAINT job_attempts_started_at_shape CHECK (
        started_at_ms IS NULL
        OR started_at_ms >= 0 AND started_at_ms <= changed_at_ms
    ),
    ADD CONSTRAINT job_attempts_lease_after_start CHECK (
        lease_issued_at_ms IS NULL
        OR started_at_ms IS NOT NULL AND lease_issued_at_ms >= started_at_ms
    );

CREATE FUNCTION automata_job_attempt_started_at_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER job_attempts_started_at_guard
BEFORE INSERT OR UPDATE ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_job_attempt_started_at_guard();
