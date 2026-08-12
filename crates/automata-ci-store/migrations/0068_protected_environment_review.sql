-- Human review completion for protected environments. Requester identity is
-- derived by the store from immutable admission evidence; a missing identity
-- can never turn `prevent_self_review` into a NULL-based approval bypass.

-- Authenticated workflow dispatch admission already emits exactly one
-- successful audit event for its run. Make that cardinality a database
-- invariant so later requester derivation never selects an arbitrary record.
CREATE UNIQUE INDEX security_audit_events_workflow_dispatch_target
    ON security_audit_events (tenant_id, resource_id)
    WHERE action = 'workflow.dispatch'
      AND resource_kind = 'workflow_run';

-- Unknown requesters may remain pending, be rejected, expire, or be cancelled.
-- They cannot produce an approved self-review-separated request. Adding this
-- as a validated constraint also refuses an upgrade over unsafe legacy proof.
ALTER TABLE protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_requester_required CHECK (
        status <> 'approved'
        OR NOT prevent_self_review
        OR requested_by_principal_id IS NOT NULL
    );

-- Decision intake is current-authority-only. An unknown requester blocks only
-- approvals; an assigned reviewer can still reject the workload explicitly.
CREATE OR REPLACE FUNCTION automata_require_environment_reviewer()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    request protected_environment_approval_requests%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    SELECT * INTO STRICT request
    FROM protected_environment_approval_requests
    WHERE tenant_id = NEW.tenant_id AND id = NEW.request_id
    FOR SHARE;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NOT automata_environment_reviewer_assignment_is_current(
        request.tenant_id, request.repository_id, request.environment_id,
        request.environment_revision, NEW.principal_id, database_now_ms
    ) THEN
        RAISE EXCEPTION 'principal is not a current environment reviewer'
            USING ERRCODE = 'insufficient_privilege',
                  CONSTRAINT = 'protected_environment_approval_decisions_reviewer';
    END IF;
    IF request.prevent_self_review
       AND NEW.decision = 'approve'
       AND request.requested_by_principal_id IS NULL THEN
        RAISE EXCEPTION 'self-review-separated request has no exact requester identity'
            USING ERRCODE = 'insufficient_privilege',
                  CONSTRAINT = 'protected_environment_approval_requester_required';
    END IF;
    IF request.prevent_self_review
       AND request.requested_by_principal_id IS NOT NULL
       AND NEW.principal_id = request.requested_by_principal_id THEN
        RAISE EXCEPTION 'requester cannot review this protected environment request'
            USING ERRCODE = 'insufficient_privilege',
                  CONSTRAINT = 'protected_environment_approval_decisions_self_review';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Continuously re-prove the non-NULL requester boundary at every credential
-- exposure check, independently of the request-row CHECK constraint.
CREATE OR REPLACE FUNCTION automata_protected_environment_approval_is_current(
    target_tenant_id TEXT,
    target_request_id UUID,
    target_now_ms BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
PARALLEL UNSAFE
AS $automata$
SELECT EXISTS (
    SELECT 1
    FROM protected_environment_approval_requests AS request
    JOIN repository_environments AS environment
      ON environment.tenant_id = request.tenant_id
     AND environment.repository_id = request.repository_id
     AND environment.id = request.environment_id
    WHERE request.tenant_id = $1
      AND request.id = $2
      AND request.status = 'approved'
      AND request.resolution_reason = 'approval_threshold_met'
      AND request.resolved_at_ms IS NOT NULL
      AND request.resolved_at_ms < request.expires_at_ms
      AND $3 < request.expires_at_ms
      AND environment.status = 'active'
      AND environment.protection_mode = 'required_approvals'
      AND environment.revision = request.environment_revision
      AND environment.required_approvals = request.required_approvals
      AND environment.prevent_self_review = request.prevent_self_review
      AND (
          NOT request.prevent_self_review
          OR request.requested_by_principal_id IS NOT NULL
      )
      AND (
          SELECT count(*)
          FROM protected_environment_approval_decisions AS decision
          WHERE decision.tenant_id = request.tenant_id
            AND decision.request_id = request.id
            AND decision.decision = 'approve'
            AND (
                NOT request.prevent_self_review
                OR decision.principal_id <> request.requested_by_principal_id
            )
            AND automata_environment_reviewer_assignment_is_current(
                request.tenant_id, request.repository_id, request.environment_id,
                request.environment_revision, decision.principal_id, $3
            )
      ) >= request.required_approvals
      AND NOT EXISTS (
          SELECT 1
          FROM protected_environment_approval_decisions AS decision
          WHERE decision.tenant_id = request.tenant_id
            AND decision.request_id = request.id
            AND decision.decision = 'reject'
            AND automata_environment_reviewer_assignment_is_current(
                request.tenant_id, request.repository_id, request.environment_id,
                request.environment_revision, decision.principal_id, $3
            )
      )
);
$automata$;
