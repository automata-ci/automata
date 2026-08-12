-- Replay-safe, value-free managed-secret delivery authority.
--
-- Plaintext secret material and bearer credentials are deliberately absent
-- from this schema. Delivery operations retain only exact workload evidence
-- and a SHA-256 verifier for the separately transported credential.

-- A terminal attempt must never become live again. A later retry is a new
-- attempt row and therefore receives a distinct attempt and lease fence.
CREATE FUNCTION automata_job_attempt_terminal_monotonic()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER job_attempts_terminal_monotonic
BEFORE UPDATE ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_job_attempt_terminal_monotonic();

CREATE UNIQUE INDEX job_attempts_one_current_per_job
    ON job_attempts (job_id)
    WHERE lifecycle IN (
        'queued', 'leased', 'preparing', 'running', 'cancelling', 'finalizing'
    );

-- Environment revisions are monotonic and change exactly when delivery-
-- relevant settings change. This prevents an approval from surviving an ABA
-- settings change that happens to restore the same visible values.
CREATE FUNCTION automata_repository_environment_revision_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    settings_changed BOOLEAN;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.normalized_name IS DISTINCT FROM OLD.normalized_name
       OR NEW.created_by_principal_id IS DISTINCT FROM OLD.created_by_principal_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'protected environment identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'repository_environments_identity_immutable';
    END IF;

    settings_changed :=
        NEW.protection_mode IS DISTINCT FROM OLD.protection_mode
        OR NEW.required_approvals IS DISTINCT FROM OLD.required_approvals
        OR NEW.prevent_self_review IS DISTINCT FROM OLD.prevent_self_review
        OR NEW.status IS DISTINCT FROM OLD.status;
    IF settings_changed AND NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'protected environment settings require one revision increment'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'repository_environments_revision_guard';
    ELSIF NOT settings_changed AND NEW.revision <> OLD.revision THEN
        RAISE EXCEPTION 'protected environment revision changed without settings'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'repository_environments_revision_guard';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER repository_environments_revision_guard
BEFORE UPDATE ON repository_environments
FOR EACH ROW
EXECUTE FUNCTION automata_repository_environment_revision_guard();

-- There is no honest way to infer which mutable environment revision an old
-- approval reviewed. Operators must drain those requests before upgrading;
-- assigning today's revision would falsely bless stale evidence after ABA.
DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM protected_environment_approval_requests) THEN
        RAISE EXCEPTION 'managed-secret delivery migration requires all protected environment approval requests to be drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_revision_backfill_refused';
    END IF;
END;
$automata$;

ALTER TABLE protected_environment_approval_requests
    ADD COLUMN environment_revision BIGINT;

ALTER TABLE protected_environment_approval_requests
    ALTER COLUMN environment_revision SET NOT NULL,
    ADD CONSTRAINT protected_environment_approval_environment_revision_positive
        CHECK (environment_revision > 0);

CREATE FUNCTION automata_protected_environment_approval_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    environment repository_environments%ROWTYPE;
    policy_is_current BOOLEAN;
    database_now_ms BIGINT;
BEGIN
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND id = NEW.environment_id
    FOR SHARE;

    IF TG_OP = 'INSERT' THEN
        IF NEW.environment_revision IS NULL THEN
            NEW.environment_revision := environment.revision;
        END IF;
        IF NEW.status <> 'pending'
           OR NEW.required_approvals <> environment.required_approvals
           OR NEW.prevent_self_review <> environment.prevent_self_review
           OR NEW.environment_revision <> environment.revision
           OR environment.protection_mode <> 'required_approvals'
           OR environment.status <> 'active' THEN
            RAISE EXCEPTION 'approval request does not snapshot the current environment'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_snapshot';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.required_approvals IS DISTINCT FROM OLD.required_approvals
       OR NEW.prevent_self_review IS DISTINCT FROM OLD.prevent_self_review
       OR NEW.requested_by_principal_id IS DISTINCT FROM OLD.requested_by_principal_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
       OR NEW.environment_revision IS DISTINCT FROM OLD.environment_revision THEN
        RAISE EXCEPTION 'approval request evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'protected_environment_approval_evidence_immutable';
    END IF;
    IF OLD.status <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal approval requests are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'protected_environment_approval_terminal_monotonic';
    END IF;
    IF OLD.status = 'pending' AND NEW.status <> 'pending'
       AND NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'approval resolution requires one revision increment'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'protected_environment_approval_revision_guard';
    ELSIF OLD.status = 'pending' AND NEW.status = 'pending'
          AND NEW.revision <> OLD.revision THEN
        RAISE EXCEPTION 'pending approval revision is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'protected_environment_approval_revision_guard';
    END IF;

    IF OLD.status = 'pending' AND NEW.status <> 'pending' THEN
        policy_is_current :=
            OLD.environment_revision = environment.revision
            AND OLD.required_approvals = environment.required_approvals
            AND OLD.prevent_self_review = environment.prevent_self_review
            AND environment.protection_mode = 'required_approvals'
            AND environment.status = 'active';

        IF NEW.resolved_at_ms IS NULL
           OR NEW.resolved_at_ms > database_now_ms
           OR database_now_ms - NEW.resolved_at_ms > 60000 THEN
            RAISE EXCEPTION 'approval resolution time is not current database time'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_resolution_time';
        END IF;

        IF NEW.status IN ('approved', 'rejected')
           AND (
               NOT policy_is_current
               OR NEW.resolved_at_ms IS NULL
               OR NEW.resolved_at_ms >= OLD.expires_at_ms
               OR database_now_ms >= OLD.expires_at_ms
           ) THEN
            RAISE EXCEPTION 'approval resolution no longer matches current environment policy'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_resolution_current';
        END IF;

        IF NOT policy_is_current
           AND NOT (
               NEW.status = 'cancelled'
               AND NEW.resolution_reason = CASE
                   WHEN environment.status = 'disabled'
                       THEN 'environment_disabled'
                   ELSE 'policy_changed'
               END
           )
           AND NOT (
               NEW.status = 'expired'
               AND NEW.resolution_reason = 'approval_expired'
               AND NEW.resolved_at_ms >= OLD.expires_at_ms
           ) THEN
            RAISE EXCEPTION 'stale approval requires a typed cancellation or expiry'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_stale_resolution';
        END IF;

        IF NEW.status = 'expired'
           AND (
               NEW.resolved_at_ms < OLD.expires_at_ms
               OR database_now_ms < OLD.expires_at_ms
           ) THEN
            RAISE EXCEPTION 'approval cannot expire before its deadline'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_expiry_time';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER protected_environment_approval_snapshot
BEFORE INSERT OR UPDATE ON protected_environment_approval_requests
FOR EACH ROW
EXECUTE FUNCTION automata_protected_environment_approval_snapshot();

-- A review decision is useful only for the exact current environment policy
-- snapshot and within the request's exclusive lifetime. Replacing the original
-- validator preserves its self-review rule while closing stale/disabled/ABA
-- decision admission.
CREATE OR REPLACE FUNCTION automata_validate_environment_approval_decision()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    request protected_environment_approval_requests%ROWTYPE;
    environment repository_environments%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    SELECT * INTO STRICT request
    FROM protected_environment_approval_requests
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.request_id
    FOR SHARE;

    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = request.tenant_id
      AND repository_id = request.repository_id
      AND id = request.environment_id
    FOR SHARE;

    IF request.status <> 'pending' THEN
        RAISE EXCEPTION 'environment approval request is terminal'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_pending';
    END IF;
    IF request.environment_revision <> environment.revision
       OR request.required_approvals <> environment.required_approvals
       OR request.prevent_self_review <> environment.prevent_self_review
       OR environment.protection_mode <> 'required_approvals'
       OR environment.status <> 'active' THEN
        RAISE EXCEPTION 'environment approval request policy is stale'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_current_policy';
    END IF;
    IF NEW.decided_at_ms < request.created_at_ms
       OR NEW.decided_at_ms >= request.expires_at_ms
       OR NEW.decided_at_ms > database_now_ms
       OR database_now_ms - NEW.decided_at_ms > 60000
       OR database_now_ms >= request.expires_at_ms THEN
        RAISE EXCEPTION 'environment approval decision is outside the request lifetime'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_lifetime';
    END IF;
    IF request.prevent_self_review
       AND request.requested_by_principal_id = NEW.principal_id THEN
        RAISE EXCEPTION 'environment requester cannot approve their own workload'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_self_review';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_protected_environment_decision_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'protected environment decisions are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'protected_environment_approval_decisions_immutable';
END;
$automata$;

CREATE TRIGGER protected_environment_approval_decisions_immutable
BEFORE UPDATE OR DELETE ON protected_environment_approval_decisions
FOR EACH ROW
EXECUTE FUNCTION automata_protected_environment_decision_immutable();

CREATE TRIGGER protected_environment_approval_decisions_no_truncate
BEFORE TRUNCATE ON protected_environment_approval_decisions
FOR EACH STATEMENT
EXECUTE FUNCTION automata_protected_environment_decision_immutable();

CREATE FUNCTION automata_secret_workload_grant_terminal_monotonic()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.status <> 'active' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal secret workload grants are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_workload_grants_terminal_monotonic';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_workload_grants_terminal_monotonic
BEFORE UPDATE ON secret_workload_grants
FOR EACH ROW
EXECUTE FUNCTION automata_secret_workload_grant_terminal_monotonic();

-- The legacy grant validator established scope and status, but did not bind an
-- approved request to the current environment revision/settings or its
-- exclusive lifetime. This second insert guard composes with it and fails
-- closed for disabled, ABA-mutated, expired, or gratuitous approval evidence.
CREATE FUNCTION automata_secret_workload_grant_environment_current()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    environment repository_environments%ROWTYPE;
    approval protected_environment_approval_requests%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    IF NEW.environment_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND id = NEW.environment_id
    FOR SHARE;

    IF environment.status <> 'active' THEN
        RAISE EXCEPTION 'environment is not active'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_environment_current';
    END IF;

    IF environment.protection_mode = 'unprotected' THEN
        IF NEW.environment_approval_request_id IS NOT NULL THEN
            RAISE EXCEPTION 'unprotected environment cannot use approval evidence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'secret_workload_grants_environment_current';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.environment_approval_request_id IS NULL THEN
        RAISE EXCEPTION 'protected environment approval is required'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_environment_current';
    END IF;

    SELECT * INTO STRICT approval
    FROM protected_environment_approval_requests
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND environment_id = NEW.environment_id
      AND run_id = NEW.run_id
      AND job_id = NEW.job_id
      AND attempt_id = NEW.attempt_id
      AND id = NEW.environment_approval_request_id
    FOR SHARE;

    IF approval.status <> 'approved'
       OR approval.environment_revision <> environment.revision
       OR approval.required_approvals <> environment.required_approvals
       OR approval.prevent_self_review <> environment.prevent_self_review
       OR approval.resolved_at_ms IS NULL
       OR approval.resolved_at_ms >= approval.expires_at_ms
       OR NEW.issued_at_ms < approval.resolved_at_ms
       OR NEW.issued_at_ms >= approval.expires_at_ms
       OR NEW.issued_at_ms > database_now_ms
       OR database_now_ms >= approval.expires_at_ms
       OR database_now_ms >= NEW.expires_at_ms THEN
        RAISE EXCEPTION 'protected environment approval is stale or expired'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_environment_current';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_workload_grants_environment_current
BEFORE INSERT ON secret_workload_grants
FOR EACH ROW
EXECUTE FUNCTION automata_secret_workload_grant_environment_current();

CREATE TABLE managed_secret_delivery_operations (
    tenant_id TEXT NOT NULL,
    operation_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    run_id UUID NOT NULL,
    job_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    lease_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    runner_slot SMALLINT NOT NULL,
    runtime_context_digest BYTEA NOT NULL,
    binding_set_digest BYTEA NOT NULL,
    authority_evidence_digest BYTEA NOT NULL,
    credential_key_id TEXT NOT NULL,
    credential_sha256 BYTEA NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    created_at_ms BIGINT NOT NULL,
    usable_until_ms BIGINT NOT NULL,
    acknowledged_at_ms BIGINT,
    CONSTRAINT managed_secret_delivery_operations_primary_key
        PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT managed_secret_delivery_operations_operation_unique
        UNIQUE (operation_id),
    CONSTRAINT managed_secret_delivery_operations_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT managed_secret_delivery_operations_repository_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT managed_secret_delivery_operations_run_job
        FOREIGN KEY (run_id, job_id)
        REFERENCES jobs(run_id, id) ON DELETE RESTRICT,
    CONSTRAINT managed_secret_delivery_operations_job_attempt
        FOREIGN KEY (job_id, attempt_id)
        REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT,
    CONSTRAINT managed_secret_delivery_operations_runner
        FOREIGN KEY (runner_id) REFERENCES runners(id) ON DELETE RESTRICT,
    CONSTRAINT managed_secret_delivery_operations_session
        FOREIGN KEY (runner_session_id)
        REFERENCES runner_sessions(id) ON DELETE RESTRICT,
    CONSTRAINT managed_secret_delivery_operations_exact_workload UNIQUE (
        tenant_id, attempt_id, lease_id, fencing_token,
        runner_session_id, runner_session_epoch, runner_generation, runner_slot,
        runtime_context_digest, binding_set_digest
    ),
    CONSTRAINT managed_secret_delivery_operations_credential_unique UNIQUE (
        credential_key_id, credential_sha256
    ),
    CONSTRAINT managed_secret_delivery_operations_fences_positive CHECK (
        fencing_token > 0
        AND runner_session_epoch > 0
        AND runner_generation > 0
        AND runner_slot > 0
    ),
    CONSTRAINT managed_secret_delivery_operations_digests CHECK (
        octet_length(runtime_context_digest) = 32
        AND octet_length(binding_set_digest) = 32
        AND octet_length(authority_evidence_digest) = 32
        AND octet_length(credential_sha256) = 32
    ),
    CONSTRAINT managed_secret_delivery_operations_key_shape CHECK (
        octet_length(credential_key_id) BETWEEN 1 AND 128
        AND credential_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT managed_secret_delivery_operations_state CHECK (
        state IN ('pending', 'acknowledged', 'expired')
    ),
    CONSTRAINT managed_secret_delivery_operations_lifetime CHECK (
        created_at_ms >= 0 AND usable_until_ms > created_at_ms
    ),
    CONSTRAINT managed_secret_delivery_operations_state_shape CHECK ((
        (state = 'pending' AND acknowledged_at_ms IS NULL)
        OR (
            state = 'acknowledged'
            AND acknowledged_at_ms >= created_at_ms
            AND acknowledged_at_ms < usable_until_ms
        )
        OR (state = 'expired' AND acknowledged_at_ms IS NULL)
    ) IS TRUE)
);

CREATE INDEX managed_secret_delivery_operations_pending
    ON managed_secret_delivery_operations (tenant_id, usable_until_ms, operation_id)
    WHERE state = 'pending';

CREATE FUNCTION automata_managed_secret_delivery_operation_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.lease_id IS DISTINCT FROM OLD.lease_id
       OR NEW.fencing_token IS DISTINCT FROM OLD.fencing_token
       OR NEW.runner_id IS DISTINCT FROM OLD.runner_id
       OR NEW.runner_session_id IS DISTINCT FROM OLD.runner_session_id
       OR NEW.runner_session_epoch IS DISTINCT FROM OLD.runner_session_epoch
       OR NEW.runner_generation IS DISTINCT FROM OLD.runner_generation
       OR NEW.runner_slot IS DISTINCT FROM OLD.runner_slot
       OR NEW.runtime_context_digest IS DISTINCT FROM OLD.runtime_context_digest
       OR NEW.binding_set_digest IS DISTINCT FROM OLD.binding_set_digest
       OR NEW.authority_evidence_digest IS DISTINCT FROM OLD.authority_evidence_digest
       OR NEW.credential_key_id IS DISTINCT FROM OLD.credential_key_id
       OR NEW.credential_sha256 IS DISTINCT FROM OLD.credential_sha256
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.usable_until_ms IS DISTINCT FROM OLD.usable_until_ms THEN
        RAISE EXCEPTION 'managed secret delivery evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'managed_secret_delivery_operations_evidence_immutable';
    END IF;
    IF OLD.state <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal managed secret delivery operations are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'managed_secret_delivery_operations_terminal_monotonic';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER managed_secret_delivery_operations_guard
BEFORE UPDATE ON managed_secret_delivery_operations
FOR EACH ROW
EXECUTE FUNCTION automata_managed_secret_delivery_operation_guard();

CREATE FUNCTION automata_managed_secret_delivery_no_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'managed secret delivery evidence is append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'managed_secret_delivery_operations_no_delete';
END;
$automata$;

CREATE TRIGGER managed_secret_delivery_operations_no_delete
BEFORE DELETE OR TRUNCATE ON managed_secret_delivery_operations
FOR EACH STATEMENT
EXECUTE FUNCTION automata_managed_secret_delivery_no_delete();

CREATE FUNCTION automata_expire_managed_secret_delivery_for_attempt()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.lifecycle IN ('leased', 'preparing', 'running')
       AND NEW.lifecycle NOT IN ('leased', 'preparing', 'running') THEN
        UPDATE managed_secret_delivery_operations
        SET state = 'expired'
        WHERE attempt_id = NEW.id AND state = 'pending';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_expire_managed_secret_delivery
AFTER UPDATE OF lifecycle ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_expire_managed_secret_delivery_for_attempt();

CREATE FUNCTION automata_expire_managed_secret_delivery_for_session()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.disconnected_at_ms IS NULL AND NEW.disconnected_at_ms IS NOT NULL THEN
        UPDATE managed_secret_delivery_operations
        SET state = 'expired'
        WHERE runner_session_id = NEW.id AND state = 'pending';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER runner_sessions_expire_managed_secret_delivery
AFTER UPDATE OF disconnected_at_ms ON runner_sessions
FOR EACH ROW
EXECUTE FUNCTION automata_expire_managed_secret_delivery_for_session();
