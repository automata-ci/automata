-- A gate that was never prepared still needs a durable terminal state after
-- its bounded selection window. Permit only pre-selection cancellation to
-- retain an intentionally unknown environment identity; waiting-gate expiry
-- continues to require its exact selected environment and approval request.

ALTER TABLE job_environment_gates
    DROP CONSTRAINT job_environment_gates_environment_shape;

ALTER TABLE job_environment_gates
    ADD CONSTRAINT job_environment_gates_environment_shape CHECK ((
        (environment_requirement_kind IN ('unclassified', 'none')
         AND environment_template_digest IS NULL
         AND environment_id IS NULL AND environment_revision IS NULL
         AND approval_request_id IS NULL)
        OR (environment_requirement_kind = 'environment'
            AND octet_length(environment_template_digest) = 32
            AND ((state = 'selection_pending'
                  AND environment_id IS NULL AND environment_revision IS NULL
                  AND approval_request_id IS NULL)
                 OR (state = 'cancelled'
                     AND ((environment_id IS NULL AND environment_revision IS NULL
                           AND approval_request_id IS NULL)
                          OR (environment_id IS NOT NULL AND environment_revision > 0)))
                 OR (state NOT IN ('selection_pending', 'cancelled')
                     AND environment_id IS NOT NULL AND environment_revision > 0)))
    ) IS TRUE);

-- Selection digests prove the chosen secret itself is current, but introducing
-- a new higher-precedence secret does not alter that digest. Re-prove the exact
-- precedence clauses at the final queued-to-leased authority boundary too.
CREATE FUNCTION automata_require_current_secret_precedence_before_lease()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    gate job_environment_gates%ROWTYPE;
BEGIN
    IF OLD.lifecycle <> 'queued' OR NEW.lifecycle <> 'leased' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM workflow_plan_v2_concrete_jobs WHERE job_id = NEW.job_id
    ) THEN
        RETURN NEW;
    END IF;
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.id AND job_id = NEW.job_id FOR SHARE;
    IF gate.state <> 'ready' THEN
        RETURN NEW;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM job_secret_selections AS selection
        WHERE selection.attempt_id = NEW.id
          AND (
              (selection.scope_kind = 'repository' AND EXISTS (
                  SELECT 1 FROM secrets AS higher
                  JOIN secret_policies AS higher_policy
                    ON higher_policy.tenant_id = higher.tenant_id
                   AND higher_policy.secret_id = higher.id
                  WHERE higher.tenant_id = gate.tenant_id
                    AND higher.repository_id = gate.repository_id
                    AND higher.environment_id = gate.environment_id
                    AND higher.scope_kind = 'environment'
                    AND higher.canonical_name = selection.canonical_name
                    AND automata_secret_is_available_to_gate(
                        higher, higher_policy, gate
                    )
              ))
              OR (selection.scope_kind = 'tenant' AND EXISTS (
                  SELECT 1 FROM secrets AS higher
                  JOIN secret_policies AS higher_policy
                    ON higher_policy.tenant_id = higher.tenant_id
                   AND higher_policy.secret_id = higher.id
                  WHERE higher.tenant_id = gate.tenant_id
                    AND higher.repository_id = gate.repository_id
                    AND higher.canonical_name = selection.canonical_name
                    AND higher.scope_kind IN ('repository', 'environment')
                    AND (higher.scope_kind = 'repository'
                         OR higher.environment_id = gate.environment_id)
                    AND automata_secret_is_available_to_gate(
                        higher, higher_policy, gate
                    )
              ))
          )
    ) THEN
        RAISE EXCEPTION 'job secret selection no longer has highest precedence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_secret_selection_precedence_current';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_require_current_secret_precedence_before_lease
BEFORE UPDATE OF lifecycle ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_require_current_secret_precedence_before_lease();
