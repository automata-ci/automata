-- Immutable deployment requirements, encrypted variable references, and
-- current-only workload binding gates.

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_concrete_jobs AS concrete
        JOIN job_attempts AS attempt ON attempt.job_id = concrete.job_id
        WHERE attempt.lifecycle IN (
            'queued', 'leased', 'preparing', 'running',
            'cancelling', 'finalizing'
        )
    ) THEN
        RAISE EXCEPTION 'credential-gate migration requires current logical attempts to be drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_environment_gates_live_backfill_refused';
    END IF;
END;
$automata$;

ALTER TABLE workflow_plan_v2_jobs
    ADD COLUMN environment_requirement_kind TEXT NOT NULL DEFAULT 'unclassified',
    ADD COLUMN environment_template_digest BYTEA,
    ADD COLUMN secret_reference_names TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN variable_reference_names TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN credential_requirements_schema SMALLINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT workflow_plan_v2_jobs_environment_requirement CHECK (
        environment_requirement_kind IN ('unclassified', 'none', 'environment')
    ),
    ADD CONSTRAINT workflow_plan_v2_jobs_environment_requirement_shape CHECK ((
        (environment_requirement_kind = 'environment'
         AND octet_length(environment_template_digest) = 32)
        OR (environment_requirement_kind IN ('unclassified', 'none')
            AND environment_template_digest IS NULL)
    ) IS TRUE),
    ADD CONSTRAINT workflow_plan_v2_jobs_reference_limits CHECK (
        cardinality(secret_reference_names) <= 256
        AND cardinality(variable_reference_names) <= 256
    ),
    ADD CONSTRAINT workflow_plan_v2_jobs_credential_schema CHECK (
        credential_requirements_schema = 1
    );

ALTER TABLE protected_environment_approval_requests
    ADD CONSTRAINT protected_environment_approval_one_per_attempt
        UNIQUE (tenant_id, attempt_id);

CREATE TABLE repository_environment_reviewers (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    environment_id UUID NOT NULL,
    environment_revision BIGINT NOT NULL,
    principal_id UUID NOT NULL,
    principal_authorization_revision BIGINT NOT NULL,
    granted_by_principal_id UUID,
    grantor_authorization_revision BIGINT,
    granted_at_ms BIGINT NOT NULL,
    CONSTRAINT repository_environment_reviewers_primary_key PRIMARY KEY (
        tenant_id, repository_id, environment_id, environment_revision, principal_id
    ),
    CONSTRAINT repository_environment_reviewers_environment
        FOREIGN KEY (tenant_id, repository_id, environment_id)
        REFERENCES repository_environments(tenant_id, repository_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT repository_environment_reviewers_principal
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT repository_environment_reviewers_grantor
        FOREIGN KEY (tenant_id, granted_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT repository_environment_reviewers_revision CHECK (
        environment_revision > 0
        AND principal_authorization_revision > 0
        AND granted_by_principal_id IS NOT NULL
        AND grantor_authorization_revision > 0
    ),
    CONSTRAINT repository_environment_reviewers_time CHECK (granted_at_ms >= 0)
);

-- Authorization is intentionally re-evaluated from the current role graph at
-- every security-sensitive write.  The recorded authorization revisions then
-- make role or membership ABA visible as a mismatch, rather than treating a
-- later restoration as evidence that an old reviewer assignment is still safe.
CREATE FUNCTION automata_principal_has_repository_permission(
    target_tenant_id TEXT,
    target_principal_id UUID,
    target_repository_id UUID,
    target_permission_name TEXT,
    target_now_ms BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
PARALLEL UNSAFE
AS $automata$
SELECT EXISTS (
    SELECT 1
    FROM tenant_human_memberships AS membership
    JOIN rbac_role_bindings AS binding
      ON binding.tenant_id = membership.tenant_id
     AND binding.principal_id = membership.principal_id
    JOIN rbac_role_permissions AS permission
      ON permission.tenant_id = binding.tenant_id
     AND permission.role_id = binding.role_id
    WHERE membership.tenant_id = $1
      AND membership.principal_id = $2
      AND membership.status = 'active'
      AND binding.status = 'active'
      AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > $5)
      AND permission.permission_name = $4
      AND (
          binding.scope_kind = 'tenant'
          OR (binding.scope_kind = 'repository'
              AND binding.repository_id = $3)
      )
);
$automata$;

-- A reviewer assignment is authority evidence, not a standing capability.  In
-- particular, an assignment is invalidated by either a reviewer or grantor
-- membership/role ABA.  Keep this predicate shared by decision intake,
-- threshold proof, and the lease gate so an approval cannot outlive the
-- authority that created it.
CREATE FUNCTION automata_environment_reviewer_assignment_is_current(
    target_tenant_id TEXT,
    target_repository_id UUID,
    target_environment_id UUID,
    target_environment_revision BIGINT,
    target_principal_id UUID,
    target_now_ms BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
PARALLEL UNSAFE
AS $automata$
SELECT EXISTS (
    SELECT 1
    FROM repository_environment_reviewers AS reviewer
    JOIN tenant_human_memberships AS reviewer_membership
      ON reviewer_membership.tenant_id = reviewer.tenant_id
     AND reviewer_membership.principal_id = reviewer.principal_id
    JOIN tenant_human_memberships AS assigning_membership
      ON assigning_membership.tenant_id = reviewer.tenant_id
     AND assigning_membership.principal_id = reviewer.granted_by_principal_id
    WHERE reviewer.tenant_id = $1
      AND reviewer.repository_id = $2
      AND reviewer.environment_id = $3
      AND reviewer.environment_revision = $4
      AND reviewer.principal_id = $5
      AND reviewer_membership.status = 'active'
      AND reviewer_membership.authorization_revision =
          reviewer.principal_authorization_revision
      AND assigning_membership.status = 'active'
      AND assigning_membership.authorization_revision =
          reviewer.grantor_authorization_revision
      AND automata_principal_has_repository_permission(
          $1, reviewer.principal_id, $2, 'environments:approve', $6
      )
      AND automata_principal_has_repository_permission(
          $1, reviewer.granted_by_principal_id, $2, 'environments:manage', $6
      )
);
$automata$;

CREATE FUNCTION automata_repository_environment_reviewer_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_revision BIGINT;
    current_status TEXT;
    current_protection TEXT;
    reviewer_status TEXT;
    reviewer_authorization_revision BIGINT;
    grantor_status TEXT;
    current_grantor_authorization_revision BIGINT;
    database_now_ms BIGINT;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'environment reviewer assignments are append-only'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'repository_environment_reviewers_append_only';
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT revision, status, protection_mode
    INTO STRICT current_revision, current_status, current_protection
    FROM repository_environments
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND id = NEW.environment_id
    FOR SHARE;
    SELECT status, authorization_revision
    INTO STRICT reviewer_status, reviewer_authorization_revision
    FROM tenant_human_memberships
    WHERE tenant_id = NEW.tenant_id AND principal_id = NEW.principal_id
    FOR SHARE;
    IF NEW.granted_by_principal_id IS NOT NULL THEN
        SELECT status, authorization_revision
        INTO STRICT grantor_status, current_grantor_authorization_revision
        FROM tenant_human_memberships
        WHERE tenant_id = NEW.tenant_id
          AND principal_id = NEW.granted_by_principal_id
        FOR SHARE;
    END IF;
    IF NEW.environment_revision <> current_revision
       OR current_status <> 'active'
       OR current_protection <> 'required_approvals'
       OR reviewer_status <> 'active'
       OR NEW.principal_authorization_revision <> reviewer_authorization_revision
       OR NOT automata_principal_has_repository_permission(
           NEW.tenant_id, NEW.principal_id, NEW.repository_id,
           'environments:approve', database_now_ms
       )
       OR grantor_status <> 'active'
       OR NEW.grantor_authorization_revision <>
          current_grantor_authorization_revision
       OR NOT automata_principal_has_repository_permission(
           NEW.tenant_id, NEW.granted_by_principal_id, NEW.repository_id,
           'environments:manage', database_now_ms
       )
       OR NEW.granted_at_ms > database_now_ms
       OR database_now_ms - NEW.granted_at_ms > 60000 THEN
        RAISE EXCEPTION 'environment reviewer assignment is stale'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'repository_environment_reviewers_current';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER repository_environment_reviewers_guard
BEFORE INSERT OR UPDATE OR DELETE ON repository_environment_reviewers
FOR EACH ROW
EXECUTE FUNCTION automata_repository_environment_reviewer_guard();

CREATE TRIGGER repository_environment_reviewers_no_truncate
BEFORE TRUNCATE ON repository_environment_reviewers
FOR EACH STATEMENT
EXECUTE FUNCTION automata_repository_environment_reviewer_guard();

CREATE FUNCTION automata_require_environment_reviewer()
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
    -- This current-assignment check includes the former
    -- protected_environment_approval_decisions_authorized permission proof,
    -- plus the grantor's current revision and manage authority.
    IF NOT automata_environment_reviewer_assignment_is_current(
        request.tenant_id, request.repository_id, request.environment_id,
        request.environment_revision, NEW.principal_id, database_now_ms
    ) THEN
        RAISE EXCEPTION 'principal is not a current environment reviewer'
            USING ERRCODE = 'insufficient_privilege',
                  CONSTRAINT = 'protected_environment_approval_decisions_reviewer';
    END IF;
    -- This is pinned on the request rather than inferred from the current
    -- environment row: a policy revision after the request was opened must
    -- never weaken the request's reviewer separation rule.  Keep this in the
    -- insert guard (rather than only in threshold proof) so a self-review is
    -- not retained as durable approval evidence at all.
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

CREATE TRIGGER protected_environment_approval_decisions_reviewer
BEFORE INSERT ON protected_environment_approval_decisions
FOR EACH ROW
EXECUTE FUNCTION automata_require_environment_reviewer();

-- The legacy request-shape constraint allows an administrative resolution
-- code.  This migration deliberately adds no such bypass: a pending request
-- becomes approved only when the exact current reviewer evidence meets the
-- pinned threshold, and rejected only on a current authorized rejection.
CREATE FUNCTION automata_prove_protected_environment_approval_resolution()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    environment repository_environments%ROWTYPE;
    database_now_ms BIGINT;
    approved_count BIGINT;
    has_rejection BOOLEAN;
BEGIN
    IF OLD.status <> 'pending' OR NEW.status = 'pending' THEN
        RETURN NEW;
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = OLD.tenant_id
      AND repository_id = OLD.repository_id
      AND id = OLD.environment_id
    FOR SHARE;

    IF NEW.status = 'approved' THEN
        IF NEW.resolution_reason <> 'approval_threshold_met'
           OR environment.status <> 'active'
           OR environment.protection_mode <> 'required_approvals'
           OR environment.revision <> OLD.environment_revision
           OR environment.required_approvals <> OLD.required_approvals
           OR environment.prevent_self_review <> OLD.prevent_self_review
           OR NEW.resolved_at_ms IS NULL
           OR NEW.resolved_at_ms >= OLD.expires_at_ms
           OR database_now_ms >= OLD.expires_at_ms THEN
            RAISE EXCEPTION 'approval resolution is not current and threshold-backed'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'protected_environment_approval_resolution_proven';
        END IF;

        SELECT count(*) INTO approved_count
        FROM protected_environment_approval_decisions AS decision
        WHERE decision.tenant_id = OLD.tenant_id
          AND decision.request_id = OLD.id
          AND decision.decision = 'approve'
          AND (
              NOT OLD.prevent_self_review
              OR OLD.requested_by_principal_id IS NULL
              OR decision.principal_id <> OLD.requested_by_principal_id
          )
          AND automata_environment_reviewer_assignment_is_current(
              OLD.tenant_id, OLD.repository_id, OLD.environment_id,
              OLD.environment_revision, decision.principal_id, database_now_ms
          );
        SELECT EXISTS (
            SELECT 1
            FROM protected_environment_approval_decisions AS decision
            WHERE decision.tenant_id = OLD.tenant_id
              AND decision.request_id = OLD.id
              AND decision.decision = 'reject'
              AND automata_environment_reviewer_assignment_is_current(
                  OLD.tenant_id, OLD.repository_id, OLD.environment_id,
                  OLD.environment_revision, decision.principal_id, database_now_ms
              )
        ) INTO has_rejection;
        IF approved_count < OLD.required_approvals OR has_rejection THEN
            RAISE EXCEPTION 'approval threshold is not proven by current distinct reviewers'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'protected_environment_approval_threshold_proven';
        END IF;
    ELSIF NEW.status = 'rejected' THEN
        IF NEW.resolution_reason <> 'approval_rejected'
           OR NOT EXISTS (
               SELECT 1
               FROM protected_environment_approval_decisions AS decision
               WHERE decision.tenant_id = OLD.tenant_id
                 AND decision.request_id = OLD.id
                 AND decision.decision = 'reject'
                 AND automata_environment_reviewer_assignment_is_current(
                     OLD.tenant_id, OLD.repository_id, OLD.environment_id,
                     OLD.environment_revision, decision.principal_id, database_now_ms
                 )
           ) THEN
            RAISE EXCEPTION 'rejection lacks current authorized reviewer evidence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'protected_environment_approval_rejection_proven';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER protected_environment_approval_threshold_proven_guard
BEFORE UPDATE ON protected_environment_approval_requests
FOR EACH ROW
EXECUTE FUNCTION automata_prove_protected_environment_approval_resolution();

-- Approval is continuously re-proven at every boundary that can expose
-- credentials.  A previously approved request is therefore not sufficient if
-- a reviewer/grantor is later revoked or their authorization revision changes.
CREATE FUNCTION automata_protected_environment_approval_is_current(
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
          SELECT count(*)
          FROM protected_environment_approval_decisions AS decision
          WHERE decision.tenant_id = request.tenant_id
            AND decision.request_id = request.id
            AND decision.decision = 'approve'
            AND (
                NOT request.prevent_self_review
                OR request.requested_by_principal_id IS NULL
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

-- Managed-secret grants are created only after the same continuously-current
-- approval proof used for leasing.  This closes the interval between a manual
-- approval and grant creation if either reviewer authority changes.
CREATE FUNCTION automata_require_current_approval_before_secret_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    environment repository_environments%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    IF NEW.environment_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND id = NEW.environment_id
    FOR SHARE;
    IF environment.protection_mode = 'required_approvals'
       AND (
           NEW.environment_approval_request_id IS NULL
           OR NOT automata_protected_environment_approval_is_current(
               NEW.tenant_id, NEW.environment_approval_request_id,
               floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
           )
       ) THEN
        RAISE EXCEPTION 'protected environment approval no longer has current reviewer authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_environment_current';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_workload_grants_current_reviewer_authority
BEFORE INSERT ON secret_workload_grants
FOR EACH ROW
EXECUTE FUNCTION automata_require_current_approval_before_secret_grant();

CREATE FUNCTION automata_validate_logical_job_credential_requirements()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    name TEXT;
    previous TEXT;
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.environment_requirement_kind IS DISTINCT FROM OLD.environment_requirement_kind
        OR NEW.environment_template_digest IS DISTINCT FROM OLD.environment_template_digest
        OR NEW.secret_reference_names IS DISTINCT FROM OLD.secret_reference_names
        OR NEW.variable_reference_names IS DISTINCT FROM OLD.variable_reference_names
        OR NEW.credential_requirements_schema IS DISTINCT FROM OLD.credential_requirements_schema
    ) THEN
        RAISE EXCEPTION 'logical job credential requirements are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_plan_v2_jobs_credential_requirements_immutable';
    END IF;

    IF COALESCE(array_ndims(NEW.secret_reference_names), 1) <> 1
       OR COALESCE(array_lower(NEW.secret_reference_names, 1), 1) <> 1
       OR array_position(NEW.secret_reference_names, NULL) IS NOT NULL
       OR COALESCE(array_ndims(NEW.variable_reference_names), 1) <> 1
       OR COALESCE(array_lower(NEW.variable_reference_names, 1), 1) <> 1
       OR array_position(NEW.variable_reference_names, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'credential references require dense one-dimensional arrays'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_jobs_credential_reference_arrays';
    END IF;

    FOREACH name IN ARRAY NEW.secret_reference_names LOOP
        IF name !~ '^[A-Z_][A-Z0-9_]*$'
           OR name ~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'
           OR octet_length(name) > 255
           OR (previous IS NOT NULL AND name <= previous) THEN
            RAISE EXCEPTION 'secret references must be sorted unique canonical names'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_plan_v2_jobs_secret_references_canonical';
        END IF;
        previous := name;
    END LOOP;

    previous := NULL;
    FOREACH name IN ARRAY NEW.variable_reference_names LOOP
        IF name !~ '^[A-Z_][A-Z0-9_]*$'
           OR name ~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'
           OR octet_length(name) > 255
           OR (previous IS NOT NULL AND name <= previous) THEN
            RAISE EXCEPTION 'variable references must be sorted unique canonical names'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_plan_v2_jobs_variable_references_canonical';
        END IF;
        previous := name;
    END LOOP;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_credential_requirements_validate
BEFORE INSERT OR UPDATE ON workflow_plan_v2_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_validate_logical_job_credential_requirements();

CREATE FUNCTION automata_require_classified_logical_job_credentials()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state <> 'pending'
       AND NEW.environment_requirement_kind = 'unclassified' THEN
        RAISE EXCEPTION 'logical job credential requirements are unclassified'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_jobs_credential_requirements_classified';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_require_classified_credentials
BEFORE UPDATE OF state ON workflow_plan_v2_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_require_classified_logical_job_credentials();

CREATE FUNCTION automata_require_classified_credentials_before_graph_seal()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.admission_graph_sealed_at_ms IS NULL
       AND NEW.admission_graph_sealed_at_ms IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM workflow_plan_v2_jobs
           WHERE run_id = NEW.run_id
             AND environment_requirement_kind = 'unclassified'
       ) THEN
        RAISE EXCEPTION 'logical graph contains unclassified credential requirements'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_runs_credential_requirements_classified';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_runs_require_classified_credentials
BEFORE UPDATE OF admission_graph_sealed_at_ms ON workflow_plan_v2_runs
FOR EACH ROW
EXECUTE FUNCTION automata_require_classified_credentials_before_graph_seal();

CREATE TABLE workflow_variables (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    repository_id UUID NOT NULL,
    environment_id UUID,
    id UUID NOT NULL,
    scope_kind TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    current_version_id UUID,
    current_version_number BIGINT,
    status TEXT NOT NULL DEFAULT 'provisioning',
    revision BIGINT NOT NULL DEFAULT 1,
    created_by_principal_id UUID,
    updated_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_variables_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT workflow_variables_scope_identity UNIQUE (
        tenant_id, id, repository_id, environment_id, scope_kind
    ),
    CONSTRAINT workflow_variables_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_variables_environment
        FOREIGN KEY (tenant_id, repository_id, environment_id)
        REFERENCES repository_environments(tenant_id, repository_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_variables_creator
        FOREIGN KEY (tenant_id, created_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_variables_updater
        FOREIGN KEY (tenant_id, updated_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_variables_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT workflow_variables_scope CHECK (
        (scope_kind = 'repository' AND environment_id IS NULL)
        OR (scope_kind = 'environment' AND environment_id IS NOT NULL)
    ),
    CONSTRAINT workflow_variables_name CHECK (
        octet_length(canonical_name) BETWEEN 1 AND 255
        AND canonical_name ~ '^[A-Z_][A-Z0-9_]*$'
        AND canonical_name !~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'
    ),
    CONSTRAINT workflow_variables_status CHECK (
        status IN ('provisioning', 'active', 'disabled', 'deleted')
    ),
    CONSTRAINT workflow_variables_head_shape CHECK ((
        (status = 'provisioning'
         AND current_version_id IS NULL AND current_version_number IS NULL)
        OR (status IN ('active', 'disabled', 'deleted')
            AND current_version_id IS NOT NULL AND current_version_number > 0)
    ) IS TRUE),
    CONSTRAINT workflow_variables_revision_positive CHECK (revision > 0),
    CONSTRAINT workflow_variables_time_monotonic CHECK (
        created_at_ms >= 0 AND updated_at_ms >= created_at_ms
    )
);

CREATE UNIQUE INDEX workflow_variables_live_repository_name
    ON workflow_variables (tenant_id, repository_id, canonical_name)
    WHERE scope_kind = 'repository' AND status <> 'deleted';

CREATE UNIQUE INDEX workflow_variables_live_environment_name
    ON workflow_variables (tenant_id, repository_id, environment_id, canonical_name)
    WHERE scope_kind = 'environment' AND status <> 'deleted';

CREATE TABLE workflow_variable_versions (
    tenant_id TEXT NOT NULL,
    id UUID NOT NULL,
    variable_id UUID NOT NULL,
    version_number BIGINT NOT NULL,
    value_object_key TEXT NOT NULL,
    value_ciphertext_sha256 BYTEA NOT NULL,
    value_size_bytes BIGINT NOT NULL,
    value_media_type TEXT NOT NULL,
    envelope_schema SMALLINT NOT NULL,
    created_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_variable_versions_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT workflow_variable_versions_identity UNIQUE (
        tenant_id, id, variable_id, version_number
    ),
    CONSTRAINT workflow_variable_versions_number_unique UNIQUE (
        tenant_id, variable_id, version_number
    ),
    CONSTRAINT workflow_variable_versions_variable
        FOREIGN KEY (tenant_id, variable_id)
        REFERENCES workflow_variables(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_variable_versions_creator
        FOREIGN KEY (tenant_id, created_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_variable_versions_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND id <> variable_id
    ),
    CONSTRAINT workflow_variable_versions_number_positive CHECK (version_number > 0),
    CONSTRAINT workflow_variable_versions_object_key CHECK (
        octet_length(value_object_key) BETWEEN 1 AND 1024
        AND value_object_key !~ '[[:cntrl:]]'
        AND left(value_object_key, 1) <> '/'
        AND value_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_variable_versions_ciphertext_digest CHECK (
        octet_length(value_ciphertext_sha256) = 32
    ),
    CONSTRAINT workflow_variable_versions_size CHECK (
        value_size_bytes BETWEEN 1 AND 1048576
    ),
    CONSTRAINT workflow_variable_versions_media_type CHECK (
        value_media_type = 'application/vnd.automata.encrypted-variable-value'
        AND envelope_schema = 1
    ),
    CONSTRAINT workflow_variable_versions_created_at CHECK (created_at_ms >= 0)
);

ALTER TABLE workflow_variables
    ADD CONSTRAINT workflow_variables_current_version
        FOREIGN KEY (tenant_id, current_version_id, id, current_version_number)
        REFERENCES workflow_variable_versions(tenant_id, id, variable_id, version_number)
        ON DELETE RESTRICT;

CREATE FUNCTION automata_workflow_variable_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.canonical_name IS DISTINCT FROM OLD.canonical_name
       OR NEW.created_by_principal_id IS DISTINCT FROM OLD.created_by_principal_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'workflow variable identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_variables_identity_immutable';
    END IF;
    IF NEW IS DISTINCT FROM OLD AND NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'workflow variable mutation requires one revision increment'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_variables_revision_guard';
    END IF;
    IF NEW.current_version_number IS DISTINCT FROM OLD.current_version_number
       AND NEW.current_version_number <> COALESCE(OLD.current_version_number, 0) + 1 THEN
        RAISE EXCEPTION 'workflow variable versions are monotonic'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_variables_version_guard';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_variables_guard
BEFORE UPDATE ON workflow_variables
FOR EACH ROW
EXECUTE FUNCTION automata_workflow_variable_guard();

CREATE FUNCTION automata_reject_workflow_variable_version_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow variable versions are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workflow_variable_versions_append_only';
END;
$automata$;

CREATE TRIGGER workflow_variable_versions_append_only
BEFORE UPDATE OR DELETE ON workflow_variable_versions
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_variable_version_mutation();

CREATE TRIGGER workflow_variable_versions_no_truncate
BEFORE TRUNCATE ON workflow_variable_versions
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_variable_version_mutation();

CREATE TABLE job_environment_gates (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    instance_id UUID NOT NULL,
    job_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    environment_requirement_kind TEXT NOT NULL,
    environment_template_digest BYTEA,
    environment_id UUID,
    environment_revision BIGINT,
    approval_request_id UUID,
    event_trust TEXT NOT NULL DEFAULT 'unknown',
    source_kind TEXT NOT NULL DEFAULT 'unknown',
    invocation_kind TEXT NOT NULL,
    reusable_secret_permission TEXT NOT NULL DEFAULT 'none',
    state TEXT NOT NULL,
    resolution_digest BYTEA,
    resolved_secret_count INTEGER,
    missing_secret_count INTEGER,
    resolved_variable_count INTEGER,
    missing_variable_count INTEGER,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT job_environment_gates_primary_key PRIMARY KEY (attempt_id),
    CONSTRAINT job_environment_gates_exact_job UNIQUE (
        tenant_id, repository_id, run_id, job_id, attempt_id
    ),
    CONSTRAINT job_environment_gates_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT job_environment_gates_repository_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE CASCADE,
    CONSTRAINT job_environment_gates_run_job
        FOREIGN KEY (run_id, job_id) REFERENCES jobs(run_id, id) ON DELETE CASCADE,
    CONSTRAINT job_environment_gates_attempt
        FOREIGN KEY (job_id, attempt_id)
        REFERENCES job_attempts(job_id, id) ON DELETE CASCADE,
    CONSTRAINT job_environment_gates_instance
        FOREIGN KEY (instance_id) REFERENCES workflow_plan_v2_concrete_jobs(instance_id)
        ON DELETE CASCADE,
    CONSTRAINT job_environment_gates_environment
        FOREIGN KEY (tenant_id, repository_id, environment_id)
        REFERENCES repository_environments(tenant_id, repository_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT job_environment_gates_approval
        FOREIGN KEY (
            tenant_id, repository_id, environment_id, run_id, job_id,
            attempt_id, approval_request_id
        ) REFERENCES protected_environment_approval_requests(
            tenant_id, repository_id, environment_id, run_id, job_id,
            attempt_id, id
        ) ON DELETE RESTRICT,
    CONSTRAINT job_environment_gates_requirement CHECK (
        environment_requirement_kind IN ('unclassified', 'none', 'environment')
    ),
    CONSTRAINT job_environment_gates_environment_shape CHECK ((
        (environment_requirement_kind IN ('unclassified', 'none')
         AND environment_template_digest IS NULL
         AND environment_id IS NULL AND environment_revision IS NULL
         AND approval_request_id IS NULL)
        OR (environment_requirement_kind = 'environment'
            AND octet_length(environment_template_digest) = 32
            AND ((state = 'selection_pending'
                  AND environment_id IS NULL AND environment_revision IS NULL
                  AND approval_request_id IS NULL)
                 OR (state <> 'selection_pending'
                     AND environment_id IS NOT NULL AND environment_revision > 0)))
    ) IS TRUE),
    CONSTRAINT job_environment_gates_event_trust CHECK (
        event_trust IN ('unknown', 'trusted', 'untrusted')
    ),
    CONSTRAINT job_environment_gates_source_kind CHECK (
        source_kind IN ('same_repository', 'fork', 'dependabot', 'unknown')
    ),
    CONSTRAINT job_environment_gates_invocation_kind CHECK (
        invocation_kind IN ('direct', 'reusable')
    ),
    CONSTRAINT job_environment_gates_reusable_permission CHECK (
        reusable_secret_permission IN ('none', 'explicit')
        AND (invocation_kind = 'reusable' OR reusable_secret_permission = 'none')
    ),
    CONSTRAINT job_environment_gates_state CHECK (
        state IN (
            'unclassified', 'selection_pending', 'waiting', 'resolving',
            'ready', 'rejected', 'expired', 'cancelled'
        )
    ),
    CONSTRAINT job_environment_gates_resolution_shape CHECK ((
        (state = 'ready'
         AND octet_length(resolution_digest) = 32
         AND resolved_secret_count >= 0 AND missing_secret_count >= 0
         AND resolved_variable_count >= 0 AND missing_variable_count >= 0)
        OR (state <> 'ready'
            AND resolution_digest IS NULL
            AND resolved_secret_count IS NULL AND missing_secret_count IS NULL
            AND resolved_variable_count IS NULL AND missing_variable_count IS NULL)
    ) IS TRUE),
    CONSTRAINT job_environment_gates_revision_positive CHECK (revision > 0),
    CONSTRAINT job_environment_gates_time CHECK (
        created_at_ms >= 0 AND updated_at_ms >= created_at_ms
    )
);

CREATE INDEX job_environment_gates_waiting
    ON job_environment_gates (tenant_id, state, updated_at_ms, attempt_id)
    WHERE state IN ('selection_pending', 'waiting', 'resolving');

CREATE TABLE job_variable_bindings (
    attempt_id UUID NOT NULL REFERENCES job_environment_gates(attempt_id) ON DELETE CASCADE,
    canonical_name TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    variable_id UUID NOT NULL,
    variable_version_id UUID NOT NULL,
    variable_version_number BIGINT NOT NULL,
    scope_kind TEXT NOT NULL,
    environment_id UUID,
    binding_digest BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT job_variable_bindings_primary_key PRIMARY KEY (attempt_id, canonical_name),
    CONSTRAINT job_variable_bindings_version
        FOREIGN KEY (
            tenant_id, variable_version_id, variable_id, variable_version_number
        ) REFERENCES workflow_variable_versions(
            tenant_id, id, variable_id, version_number
        )
        ON DELETE RESTRICT,
    CONSTRAINT job_variable_bindings_name CHECK (
        canonical_name ~ '^[A-Z_][A-Z0-9_]*$'
        AND octet_length(canonical_name) <= 255
    ),
    CONSTRAINT job_variable_bindings_scope CHECK (
        (scope_kind = 'repository' AND environment_id IS NULL)
        OR (scope_kind = 'environment' AND environment_id IS NOT NULL)
    ),
    CONSTRAINT job_variable_bindings_digest CHECK (octet_length(binding_digest) = 32),
    CONSTRAINT job_variable_bindings_created_at CHECK (created_at_ms >= 0)
);

CREATE TABLE job_missing_variable_bindings (
    attempt_id UUID NOT NULL REFERENCES job_environment_gates(attempt_id) ON DELETE CASCADE,
    canonical_name TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT job_missing_variable_bindings_primary_key PRIMARY KEY (
        attempt_id, canonical_name
    ),
    CONSTRAINT job_missing_variable_bindings_name CHECK (
        canonical_name ~ '^[A-Z_][A-Z0-9_]*$'
        AND octet_length(canonical_name) <= 255
    ),
    CONSTRAINT job_missing_variable_bindings_created_at CHECK (created_at_ms >= 0)
);

ALTER TABLE secret_workload_grants
    ADD COLUMN invocation_kind TEXT NOT NULL DEFAULT 'direct',
    ADD COLUMN reusable_secret_permission TEXT NOT NULL DEFAULT 'none',
    ADD COLUMN lease_id UUID,
    ADD CONSTRAINT secret_workload_grants_invocation_kind CHECK (
        invocation_kind IN ('direct', 'reusable')
    ),
    ADD CONSTRAINT secret_workload_grants_reusable_permission CHECK (
        reusable_secret_permission IN ('none', 'explicit')
        AND (invocation_kind = 'reusable' OR reusable_secret_permission = 'none')
    );

CREATE FUNCTION automata_secret_workload_grant_invocation_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.invocation_kind IS DISTINCT FROM OLD.invocation_kind
       OR NEW.reusable_secret_permission IS DISTINCT FROM OLD.reusable_secret_permission
       OR NEW.lease_id IS DISTINCT FROM OLD.lease_id THEN
        RAISE EXCEPTION 'secret grant invocation authority is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_workload_grants_invocation_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_workload_grants_invocation_guard
BEFORE UPDATE ON secret_workload_grants
FOR EACH ROW
EXECUTE FUNCTION automata_secret_workload_grant_invocation_guard();

CREATE TABLE job_secret_selections (
    attempt_id UUID NOT NULL REFERENCES job_environment_gates(attempt_id) ON DELETE CASCADE,
    canonical_name TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    secret_id UUID NOT NULL,
    secret_version_id UUID NOT NULL,
    secret_version_number BIGINT NOT NULL,
    scope_kind TEXT NOT NULL,
    environment_id UUID,
    binding_digest BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT job_secret_selections_primary_key PRIMARY KEY (attempt_id, canonical_name),
    CONSTRAINT job_secret_selections_version
        FOREIGN KEY (
            tenant_id, secret_version_id, secret_id, secret_version_number
        ) REFERENCES secret_versions(tenant_id, id, secret_id, version_number)
        ON DELETE RESTRICT,
    CONSTRAINT job_secret_selections_name CHECK (
        canonical_name ~ '^[A-Z_][A-Z0-9_]*$'
        AND octet_length(canonical_name) <= 255
    ),
    CONSTRAINT job_secret_selections_scope CHECK (
        scope_kind IN ('tenant', 'repository', 'environment')
    ),
    CONSTRAINT job_secret_selections_environment_shape CHECK (
        (scope_kind = 'environment') = (environment_id IS NOT NULL)
    ),
    CONSTRAINT job_secret_selections_digest CHECK (octet_length(binding_digest) = 32),
    CONSTRAINT job_secret_selections_created_at CHECK (created_at_ms >= 0)
);

CREATE TABLE job_secret_bindings (
    attempt_id UUID NOT NULL,
    canonical_name TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    grant_id UUID NOT NULL,
    lease_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    binding_digest BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT job_secret_bindings_primary_key PRIMARY KEY (attempt_id, canonical_name),
    CONSTRAINT job_secret_bindings_selection
        FOREIGN KEY (attempt_id, canonical_name)
        REFERENCES job_secret_selections(attempt_id, canonical_name) ON DELETE CASCADE,
    CONSTRAINT job_secret_bindings_grant_unique UNIQUE (tenant_id, grant_id),
    CONSTRAINT job_secret_bindings_grant
        FOREIGN KEY (tenant_id, grant_id)
        REFERENCES secret_workload_grants(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT job_secret_bindings_fence CHECK (
        fencing_token > 0
        AND lease_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT job_secret_bindings_digest CHECK (octet_length(binding_digest) = 32),
    CONSTRAINT job_secret_bindings_created_at CHECK (created_at_ms >= 0)
);

CREATE TABLE job_missing_secret_bindings (
    attempt_id UUID NOT NULL REFERENCES job_environment_gates(attempt_id) ON DELETE CASCADE,
    canonical_name TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT job_missing_secret_bindings_primary_key PRIMARY KEY (
        attempt_id, canonical_name
    ),
    CONSTRAINT job_missing_secret_bindings_name CHECK (
        canonical_name ~ '^[A-Z_][A-Z0-9_]*$'
        AND octet_length(canonical_name) <= 255
    ),
    CONSTRAINT job_missing_secret_bindings_created_at CHECK (created_at_ms >= 0)
);

CREATE FUNCTION automata_job_credential_resolution_digest(target_attempt_id UUID)
RETURNS BYTEA
LANGUAGE SQL
STABLE
PARALLEL UNSAFE
AS $automata$
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
$automata$;

CREATE FUNCTION automata_seed_job_environment_gate(
    target_instance_id UUID,
    target_job_id UUID,
    target_attempt_id UUID,
    target_created_at_ms BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $automata$
DECLARE
    logical_job workflow_plan_v2_jobs%ROWTYPE;
    concrete workflow_plan_v2_concrete_jobs%ROWTYPE;
    tenant TEXT;
    repository UUID;
    root_invocation UUID;
    initial_state TEXT;
BEGIN
    SELECT * INTO STRICT concrete
    FROM workflow_plan_v2_concrete_jobs
    WHERE instance_id = target_instance_id AND job_id = target_job_id;
    SELECT * INTO STRICT logical_job
    FROM workflow_plan_v2_jobs
    WHERE run_id = concrete.run_id
      AND invocation_id = concrete.invocation_id
      AND id = concrete.logical_job_id;
    SELECT repository_row.tenant_id, run.repository_id, marker.root_invocation_id
    INTO STRICT tenant, repository, root_invocation
    FROM workflow_runs AS run
    JOIN repositories AS repository_row ON repository_row.id = run.repository_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
    WHERE run.id = concrete.run_id;

    IF logical_job.environment_requirement_kind = 'unclassified' THEN
        initial_state := 'unclassified';
    ELSIF logical_job.environment_requirement_kind = 'none'
          AND cardinality(logical_job.secret_reference_names) = 0
          AND cardinality(logical_job.variable_reference_names) = 0 THEN
        initial_state := 'resolving';
    ELSE
        -- Selection evidence is immutable once resolution begins.  Even a
        -- no-environment job therefore pauses here until its authenticated
        -- trust/source projection has been recorded.
        initial_state := 'selection_pending';
    END IF;

    INSERT INTO job_environment_gates (
        tenant_id, repository_id, run_id, invocation_id, logical_job_id,
        instance_id, job_id, attempt_id, environment_requirement_kind,
        environment_template_digest, invocation_kind, state,
        resolution_digest, resolved_secret_count, missing_secret_count,
        resolved_variable_count, missing_variable_count,
        created_at_ms, updated_at_ms
    ) VALUES (
        tenant, repository, concrete.run_id, concrete.invocation_id,
        concrete.logical_job_id, concrete.instance_id, target_job_id,
        target_attempt_id, logical_job.environment_requirement_kind,
        logical_job.environment_template_digest,
        CASE WHEN concrete.invocation_id = root_invocation
             THEN 'direct' ELSE 'reusable' END,
        initial_state, NULL, NULL, NULL, NULL, NULL,
        target_created_at_ms, target_created_at_ms
    ) ON CONFLICT (attempt_id) DO NOTHING;

    IF logical_job.environment_requirement_kind = 'none'
       AND cardinality(logical_job.secret_reference_names) = 0
       AND cardinality(logical_job.variable_reference_names) = 0 THEN
        UPDATE job_environment_gates
        SET state = 'ready',
            resolution_digest = automata_job_credential_resolution_digest(target_attempt_id),
            resolved_secret_count = 0,
            missing_secret_count = 0,
            resolved_variable_count = 0,
            missing_variable_count = 0,
            revision = revision + 1
        WHERE attempt_id = target_attempt_id AND state = 'resolving';
    END IF;
END;
$automata$;

CREATE FUNCTION automata_seed_initial_job_environment_gate()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM automata_seed_job_environment_gate(
        NEW.instance_id, NEW.job_id, NEW.initial_attempt_id, NEW.committed_at_ms
    );
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_concrete_jobs_seed_environment_gate
AFTER INSERT ON workflow_plan_v2_concrete_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_seed_initial_job_environment_gate();

CREATE FUNCTION automata_seed_retry_job_environment_gate()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    concrete_instance UUID;
BEGIN
    SELECT instance_id INTO concrete_instance
    FROM workflow_plan_v2_concrete_jobs
    WHERE job_id = NEW.job_id;
    IF concrete_instance IS NOT NULL THEN
        PERFORM automata_seed_job_environment_gate(
            concrete_instance, NEW.job_id, NEW.id, NEW.queued_at_ms
        );
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_seed_environment_gate
AFTER INSERT ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_seed_retry_job_environment_gate();

CREATE FUNCTION automata_job_environment_gate_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER job_environment_gates_guard
BEFORE UPDATE ON job_environment_gates
FOR EACH ROW
EXECUTE FUNCTION automata_job_environment_gate_guard();

CREATE FUNCTION automata_validate_job_credential_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    gate job_environment_gates%ROWTYPE;
    logical_job workflow_plan_v2_jobs%ROWTYPE;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    SELECT * INTO STRICT logical_job FROM workflow_plan_v2_jobs
    WHERE run_id = gate.run_id AND invocation_id = gate.invocation_id
      AND id = gate.logical_job_id;
    IF TG_TABLE_NAME LIKE '%secret%' THEN
        IF NOT NEW.canonical_name = ANY(logical_job.secret_reference_names) THEN
            RAISE EXCEPTION 'secret binding was not declared by the logical job'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_secret_bindings_declared';
        END IF;
    ELSE
        IF NOT NEW.canonical_name = ANY(logical_job.variable_reference_names) THEN
            RAISE EXCEPTION 'variable binding was not declared by the logical job'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_variable_bindings_declared';
        END IF;
    END IF;
    IF gate.state <> 'resolving' THEN
        RAISE EXCEPTION 'credential bindings require a live resolving gate'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_credential_bindings_gate_live';
    END IF;
    IF TG_TABLE_NAME = 'job_secret_selections' AND EXISTS (
        SELECT 1 FROM job_missing_secret_bindings
        WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name
    ) OR TG_TABLE_NAME = 'job_missing_secret_bindings' AND EXISTS (
        SELECT 1 FROM job_secret_selections
        WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name
    ) OR TG_TABLE_NAME = 'job_variable_bindings' AND EXISTS (
        SELECT 1 FROM job_missing_variable_bindings
        WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name
    ) OR TG_TABLE_NAME = 'job_missing_variable_bindings' AND EXISTS (
        SELECT 1 FROM job_variable_bindings
        WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name
    ) THEN
        RAISE EXCEPTION 'credential name already has an opposite resolution'
            USING ERRCODE = 'unique_violation',
                  CONSTRAINT = 'job_credential_bindings_one_resolution';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_variable_bindings_validate
BEFORE INSERT ON job_variable_bindings
FOR EACH ROW EXECUTE FUNCTION automata_validate_job_credential_binding();
CREATE TRIGGER job_missing_variable_bindings_validate
BEFORE INSERT ON job_missing_variable_bindings
FOR EACH ROW EXECUTE FUNCTION automata_validate_job_credential_binding();
CREATE TRIGGER job_secret_selections_validate
BEFORE INSERT ON job_secret_selections
FOR EACH ROW EXECUTE FUNCTION automata_validate_job_credential_binding();
CREATE TRIGGER job_missing_secret_bindings_validate
BEFORE INSERT ON job_missing_secret_bindings
FOR EACH ROW EXECUTE FUNCTION automata_validate_job_credential_binding();

CREATE FUNCTION automata_job_variable_binding_digest(
    target_attempt_id UUID,
    target_name TEXT,
    target_tenant_id TEXT,
    target_variable_id UUID,
    target_version_id UUID,
    target_version_number BIGINT,
    target_scope_kind TEXT,
    target_environment_id UUID
)
RETURNS BYTEA
LANGUAGE SQL
STABLE
PARALLEL UNSAFE
AS $automata$
SELECT pg_catalog.sha256(
    convert_to('automata.store.job-variable-binding.v1', 'UTF8')
    || decode('00', 'hex') || uuid_send($1)
    || int4send(octet_length(convert_to($2, 'UTF8'))) || convert_to($2, 'UTF8')
    || int4send(octet_length(convert_to($3, 'UTF8'))) || convert_to($3, 'UTF8')
    || uuid_send($4) || uuid_send($5) || int8send($6)
    || int4send(octet_length(convert_to($7, 'UTF8'))) || convert_to($7, 'UTF8')
    || CASE WHEN $8 IS NULL THEN decode('00', 'hex')
            ELSE decode('01', 'hex') || uuid_send($8) END
    || version.value_ciphertext_sha256
    || int8send(version.value_size_bytes)
    || int2send(version.envelope_schema)
)
FROM workflow_variable_versions AS version
WHERE version.tenant_id = $3 AND version.id = $5
  AND version.variable_id = $4 AND version.version_number = $6;
$automata$;

CREATE FUNCTION automata_validate_job_variable_binding_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    gate job_environment_gates%ROWTYPE;
    variable workflow_variables%ROWTYPE;
    expected_digest BYTEA;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    SELECT * INTO STRICT variable FROM workflow_variables
    WHERE tenant_id = NEW.tenant_id AND id = NEW.variable_id FOR SHARE;
    expected_digest := automata_job_variable_binding_digest(
        NEW.attempt_id, NEW.canonical_name, NEW.tenant_id, NEW.variable_id,
        NEW.variable_version_id, NEW.variable_version_number,
        NEW.scope_kind, NEW.environment_id
    );
    IF variable.status <> 'active'
       OR variable.repository_id <> gate.repository_id
       OR variable.canonical_name <> NEW.canonical_name
       OR variable.scope_kind <> NEW.scope_kind
       OR variable.environment_id IS DISTINCT FROM NEW.environment_id
       OR variable.current_version_id <> NEW.variable_version_id
       OR variable.current_version_number <> NEW.variable_version_number
       OR expected_digest IS NULL
       OR NEW.binding_digest IS DISTINCT FROM expected_digest
       OR (NEW.scope_kind = 'environment'
           AND NEW.environment_id IS DISTINCT FROM gate.environment_id)
       OR (NEW.scope_kind = 'repository' AND EXISTS (
           SELECT 1 FROM workflow_variables AS higher
           WHERE higher.tenant_id = gate.tenant_id
             AND higher.repository_id = gate.repository_id
             AND higher.environment_id = gate.environment_id
             AND higher.scope_kind = 'environment'
             AND higher.canonical_name = NEW.canonical_name
             AND higher.status = 'active'
       )) THEN
        RAISE EXCEPTION 'variable binding is not the current highest-precedence version'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_variable_bindings_current_precedence';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_variable_bindings_exact
BEFORE INSERT ON job_variable_bindings
FOR EACH ROW EXECUTE FUNCTION automata_validate_job_variable_binding_exact();

CREATE FUNCTION automata_validate_missing_job_variable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    gate job_environment_gates%ROWTYPE;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    IF EXISTS (
        SELECT 1 FROM workflow_variables AS variable
        WHERE variable.tenant_id = gate.tenant_id
          AND variable.repository_id = gate.repository_id
          AND variable.canonical_name = NEW.canonical_name
          AND variable.status = 'active'
          AND (variable.scope_kind = 'repository'
               OR (variable.scope_kind = 'environment'
                   AND variable.environment_id = gate.environment_id))
    ) THEN
        RAISE EXCEPTION 'an available variable cannot resolve as missing'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_missing_variable_bindings_unavailable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_missing_variable_bindings_exact
BEFORE INSERT ON job_missing_variable_bindings
FOR EACH ROW EXECUTE FUNCTION automata_validate_missing_job_variable();

CREATE FUNCTION automata_secret_is_available_to_gate(
    target_secret secrets,
    target_policy secret_policies,
    target_gate job_environment_gates
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
PARALLEL UNSAFE
AS $automata$
SELECT (target_secret).status = 'active'
   AND (target_secret).current_version_id IS NOT NULL
   AND (target_policy).minimum_event_trust IN ('trusted', 'untrusted')
   AND ((target_policy).minimum_event_trust <> 'trusted'
        OR (target_gate).event_trust = 'trusted')
   AND ((target_gate).source_kind <> 'fork' OR (target_policy).allow_fork_pull_requests)
   AND ((target_gate).source_kind <> 'dependabot' OR (target_policy).allow_dependabot)
   AND (target_gate).source_kind <> 'unknown'
   AND ((target_gate).invocation_kind = 'direct'
        OR ((target_gate).reusable_secret_permission = 'explicit'
            AND (target_policy).reusable_workflow_mode = 'explicit_only'))
   AND (
       ((target_secret).scope_kind = 'environment'
        AND (target_secret).repository_id = (target_gate).repository_id
        AND (target_secret).environment_id = (target_gate).environment_id)
       OR ((target_secret).scope_kind = 'repository'
           AND (target_secret).repository_id = (target_gate).repository_id)
       OR ((target_secret).scope_kind = 'tenant'
           AND ((target_policy).tenant_repository_access_mode = 'all_repositories'
                OR EXISTS (
                    SELECT 1 FROM secret_repository_access AS access
                    WHERE access.tenant_id = (target_secret).tenant_id
                      AND access.secret_id = (target_secret).id
                      AND access.repository_id = (target_gate).repository_id
                )))
   );
$automata$;

CREATE FUNCTION automata_job_secret_selection_digest(
    target_attempt_id UUID,
    target_name TEXT,
    target_tenant_id TEXT,
    target_secret_id UUID,
    target_version_id UUID,
    target_version_number BIGINT,
    target_scope_kind TEXT,
    target_environment_id UUID
)
RETURNS BYTEA
LANGUAGE SQL
STABLE
PARALLEL UNSAFE
AS $automata$
SELECT pg_catalog.sha256(
    convert_to('automata.store.job-secret-selection.v1', 'UTF8')
    || decode('00', 'hex') || uuid_send($1)
    || int4send(octet_length(convert_to($2, 'UTF8'))) || convert_to($2, 'UTF8')
    || int4send(octet_length(convert_to($3, 'UTF8'))) || convert_to($3, 'UTF8')
    || uuid_send($4) || uuid_send($5) || int8send($6)
    || int4send(octet_length(convert_to($7, 'UTF8'))) || convert_to($7, 'UTF8')
    || CASE WHEN $8 IS NULL THEN decode('00', 'hex')
            ELSE decode('01', 'hex') || uuid_send($8) END
    || int8send(policy.revision)
    || int8send(secret.revision)
    || int4send(octet_length(convert_to(gate.event_trust, 'UTF8')))
    || convert_to(gate.event_trust, 'UTF8')
    || int4send(octet_length(convert_to(gate.source_kind, 'UTF8')))
    || convert_to(gate.source_kind, 'UTF8')
    || int4send(octet_length(convert_to(gate.invocation_kind, 'UTF8')))
    || convert_to(gate.invocation_kind, 'UTF8')
)
FROM secrets AS secret
JOIN secret_policies AS policy
  ON policy.tenant_id = secret.tenant_id AND policy.secret_id = secret.id
JOIN job_environment_gates AS gate ON gate.attempt_id = $1
WHERE secret.tenant_id = $3 AND secret.id = $4
  AND secret.current_version_id = $5 AND secret.current_version_number = $6;
$automata$;

CREATE FUNCTION automata_validate_job_secret_selection_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    gate job_environment_gates%ROWTYPE;
    secret secrets%ROWTYPE;
    policy secret_policies%ROWTYPE;
    expected_digest BYTEA;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    SELECT * INTO STRICT secret FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id FOR SHARE;
    SELECT * INTO STRICT policy FROM secret_policies
    WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id FOR SHARE;
    expected_digest := automata_job_secret_selection_digest(
        NEW.attempt_id, NEW.canonical_name, NEW.tenant_id, NEW.secret_id,
        NEW.secret_version_id, NEW.secret_version_number,
        NEW.scope_kind, NEW.environment_id
    );
    IF secret.canonical_name <> NEW.canonical_name
       OR secret.scope_kind <> NEW.scope_kind
       OR secret.environment_id IS DISTINCT FROM NEW.environment_id
       OR secret.current_version_id <> NEW.secret_version_id
       OR secret.current_version_number <> NEW.secret_version_number
       OR NOT automata_secret_is_available_to_gate(secret, policy, gate)
       OR expected_digest IS NULL
       OR NEW.binding_digest IS DISTINCT FROM expected_digest
       OR (NEW.scope_kind = 'repository' AND EXISTS (
           SELECT 1 FROM secrets AS higher
           JOIN secret_policies AS higher_policy
             ON higher_policy.tenant_id = higher.tenant_id
            AND higher_policy.secret_id = higher.id
           WHERE higher.tenant_id = gate.tenant_id
             AND higher.repository_id = gate.repository_id
             AND higher.environment_id = gate.environment_id
             AND higher.scope_kind = 'environment'
             AND higher.canonical_name = NEW.canonical_name
             AND automata_secret_is_available_to_gate(higher, higher_policy, gate)
       ))
       OR (NEW.scope_kind = 'tenant' AND EXISTS (
           SELECT 1 FROM secrets AS higher
           JOIN secret_policies AS higher_policy
             ON higher_policy.tenant_id = higher.tenant_id
            AND higher_policy.secret_id = higher.id
           WHERE higher.tenant_id = gate.tenant_id
             AND higher.repository_id = gate.repository_id
             AND higher.canonical_name = NEW.canonical_name
             AND higher.scope_kind IN ('repository', 'environment')
             AND (higher.scope_kind = 'repository'
                  OR higher.environment_id = gate.environment_id)
             AND automata_secret_is_available_to_gate(higher, higher_policy, gate)
       )) THEN
        RAISE EXCEPTION 'secret selection is not current, permitted, or highest precedence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_secret_selections_current_precedence';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_secret_selections_exact
BEFORE INSERT ON job_secret_selections
FOR EACH ROW EXECUTE FUNCTION automata_validate_job_secret_selection_exact();

CREATE FUNCTION automata_validate_missing_job_secret()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    gate job_environment_gates%ROWTYPE;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    IF EXISTS (
        SELECT 1 FROM secrets AS secret
        JOIN secret_policies AS policy
          ON policy.tenant_id = secret.tenant_id AND policy.secret_id = secret.id
        WHERE secret.tenant_id = gate.tenant_id
          AND secret.canonical_name = NEW.canonical_name
          AND automata_secret_is_available_to_gate(secret, policy, gate)
    ) THEN
        RAISE EXCEPTION 'an available secret cannot resolve as missing'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_missing_secret_bindings_unavailable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_missing_secret_bindings_exact
BEFORE INSERT ON job_missing_secret_bindings
FOR EACH ROW EXECUTE FUNCTION automata_validate_missing_job_secret();

CREATE FUNCTION automata_job_secret_binding_digest(
    target_attempt_id UUID,
    target_name TEXT,
    target_tenant_id TEXT,
    target_grant_id UUID,
    target_lease_id UUID,
    target_fencing_token BIGINT
)
RETURNS BYTEA
LANGUAGE SQL
STABLE
PARALLEL UNSAFE
AS $automata$
SELECT pg_catalog.sha256(
    convert_to('automata.store.job-secret-binding.v1', 'UTF8')
    || decode('00', 'hex') || uuid_send($1)
    || int4send(octet_length(convert_to($2, 'UTF8'))) || convert_to($2, 'UTF8')
    || int4send(octet_length(convert_to($3, 'UTF8'))) || convert_to($3, 'UTF8')
    || uuid_send($4) || uuid_send($5) || int8send($6)
    || workload_grant.authority_digest
    || int8send(workload_grant.expires_at_ms)
)
FROM secret_workload_grants AS workload_grant
WHERE workload_grant.tenant_id = $3 AND workload_grant.id = $4;
$automata$;

CREATE FUNCTION automata_validate_job_secret_binding_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    gate job_environment_gates%ROWTYPE;
    selection job_secret_selections%ROWTYPE;
    workload_grant secret_workload_grants%ROWTYPE;
    attempt job_attempts%ROWTYPE;
    database_now_ms BIGINT;
    expected_digest BYTEA;
BEGIN
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    SELECT * INTO STRICT selection FROM job_secret_selections
    WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name FOR SHARE;
    SELECT * INTO STRICT workload_grant FROM secret_workload_grants
    WHERE tenant_id = NEW.tenant_id AND id = NEW.grant_id FOR SHARE;
    SELECT * INTO STRICT attempt FROM job_attempts
    WHERE id = NEW.attempt_id FOR SHARE;
    expected_digest := automata_job_secret_binding_digest(
        NEW.attempt_id, NEW.canonical_name, NEW.tenant_id, NEW.grant_id,
        NEW.lease_id, NEW.fencing_token
    );
    IF attempt.lifecycle <> 'leased'
       OR attempt.lease_id <> NEW.lease_id
       OR attempt.fencing_token <> NEW.fencing_token
       OR attempt.lease_expires_at_ms IS NULL
       OR database_now_ms >= attempt.lease_expires_at_ms
       OR selection.tenant_id <> NEW.tenant_id
       OR workload_grant.repository_id <> gate.repository_id
       OR workload_grant.run_id <> gate.run_id
       OR workload_grant.job_id <> gate.job_id
       OR workload_grant.attempt_id <> gate.attempt_id
       OR workload_grant.secret_id <> selection.secret_id
       OR workload_grant.secret_version_id <> selection.secret_version_id
       OR workload_grant.secret_version_number <> selection.secret_version_number
       OR workload_grant.environment_id IS DISTINCT FROM gate.environment_id
       OR workload_grant.environment_approval_request_id IS DISTINCT FROM gate.approval_request_id
       OR workload_grant.event_trust <> gate.event_trust
       OR workload_grant.source_kind <> gate.source_kind
       OR workload_grant.invocation_kind <> gate.invocation_kind
       OR workload_grant.reusable_secret_permission <> gate.reusable_secret_permission
       OR workload_grant.grant_mode <> 'readable_secret'
       OR workload_grant.lease_id <> NEW.lease_id
       OR workload_grant.fencing_token <> NEW.fencing_token
       OR workload_grant.status <> 'active'
       OR workload_grant.issued_at_ms > database_now_ms
       OR database_now_ms >= workload_grant.expires_at_ms
       OR workload_grant.expires_at_ms > attempt.lease_expires_at_ms
       OR expected_digest IS NULL
       OR NEW.binding_digest IS DISTINCT FROM expected_digest THEN
        RAISE EXCEPTION 'secret binding is not exact for the live lease fence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_secret_bindings_live_lease_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_secret_bindings_exact
BEFORE INSERT ON job_secret_bindings
FOR EACH ROW EXECUTE FUNCTION automata_validate_job_secret_binding_exact();

CREATE FUNCTION automata_require_job_environment_gate_before_lease()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    gate job_environment_gates%ROWTYPE;
    environment repository_environments%ROWTYPE;
    approval protected_environment_approval_requests%ROWTYPE;
    logical_job workflow_plan_v2_jobs%ROWTYPE;
    database_now_ms BIGINT;
    secret_count BIGINT;
    missing_secret_count BIGINT;
    variable_count BIGINT;
    missing_variable_count BIGINT;
BEGIN
    IF OLD.lifecycle <> 'queued' OR NEW.lifecycle <> 'leased' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM workflow_plan_v2_concrete_jobs WHERE job_id = NEW.job_id
    ) THEN
        RETURN NEW;
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.id AND job_id = NEW.job_id FOR SHARE;
    SELECT * INTO STRICT logical_job FROM workflow_plan_v2_jobs
    WHERE run_id = gate.run_id AND invocation_id = gate.invocation_id
      AND id = gate.logical_job_id FOR SHARE;
    IF gate.state <> 'ready'
       OR gate.environment_requirement_kind <> logical_job.environment_requirement_kind
       OR gate.environment_template_digest IS DISTINCT FROM logical_job.environment_template_digest
       OR gate.resolution_digest IS NULL
       OR gate.event_trust = 'unknown' AND cardinality(logical_job.secret_reference_names) > 0
       OR gate.source_kind = 'unknown' AND cardinality(logical_job.secret_reference_names) > 0
       OR gate.invocation_kind = 'reusable'
          AND cardinality(logical_job.secret_reference_names) > 0
          AND gate.reusable_secret_permission <> 'explicit' THEN
        RAISE EXCEPTION 'job environment and credential gate is not ready'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_environment_gate_ready';
    END IF;

    SELECT count(*) INTO secret_count FROM job_secret_selections WHERE attempt_id = NEW.id;
    SELECT count(*) INTO missing_secret_count FROM job_missing_secret_bindings WHERE attempt_id = NEW.id;
    SELECT count(*) INTO variable_count FROM job_variable_bindings WHERE attempt_id = NEW.id;
    SELECT count(*) INTO missing_variable_count FROM job_missing_variable_bindings WHERE attempt_id = NEW.id;
    IF secret_count <> gate.resolved_secret_count
       OR missing_secret_count <> gate.missing_secret_count
       OR variable_count <> gate.resolved_variable_count
       OR missing_variable_count <> gate.missing_variable_count
       OR secret_count + missing_secret_count <> cardinality(logical_job.secret_reference_names)
       OR variable_count + missing_variable_count <> cardinality(logical_job.variable_reference_names) THEN
        RAISE EXCEPTION 'job credential resolution is incomplete'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_credential_resolution_complete';
    END IF;
    IF EXISTS (
        SELECT 1 FROM job_secret_selections AS selection
        WHERE selection.attempt_id = NEW.id
          AND selection.binding_digest IS DISTINCT FROM automata_job_secret_selection_digest(
              selection.attempt_id, selection.canonical_name, selection.tenant_id,
              selection.secret_id, selection.secret_version_id,
              selection.secret_version_number, selection.scope_kind,
              selection.environment_id
          )
    ) OR EXISTS (
        SELECT 1 FROM job_variable_bindings AS binding
        WHERE binding.attempt_id = NEW.id
          AND binding.binding_digest IS DISTINCT FROM automata_job_variable_binding_digest(
              binding.attempt_id, binding.canonical_name, binding.tenant_id,
              binding.variable_id, binding.variable_version_id,
              binding.variable_version_number, binding.scope_kind,
              binding.environment_id
          )
    ) THEN
        RAISE EXCEPTION 'job credential selection is no longer current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_credential_selection_current';
    END IF;

    IF gate.environment_id IS NOT NULL THEN
        SELECT * INTO STRICT environment FROM repository_environments
        WHERE tenant_id = gate.tenant_id AND repository_id = gate.repository_id
          AND id = gate.environment_id FOR SHARE;
        IF environment.status <> 'active'
           OR environment.revision <> gate.environment_revision THEN
            RAISE EXCEPTION 'job environment policy is stale'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_attempts_environment_gate_current';
        END IF;
        IF environment.protection_mode = 'required_approvals' THEN
            SELECT * INTO STRICT approval FROM protected_environment_approval_requests
            WHERE tenant_id = gate.tenant_id AND id = gate.approval_request_id FOR SHARE;
            IF approval.status <> 'approved'
               OR approval.environment_revision <> environment.revision
               OR approval.required_approvals <> environment.required_approvals
               OR approval.prevent_self_review <> environment.prevent_self_review
               OR approval.resolved_at_ms IS NULL
               OR approval.resolved_at_ms >= approval.expires_at_ms
               OR database_now_ms >= approval.expires_at_ms
               OR NOT automata_protected_environment_approval_is_current(
                   gate.tenant_id, gate.approval_request_id, database_now_ms
               ) THEN
                RAISE EXCEPTION 'protected environment approval is stale'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'job_attempts_environment_approval_current';
            END IF;
        ELSIF gate.approval_request_id IS NOT NULL THEN
            RAISE EXCEPTION 'unprotected environment has approval evidence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_attempts_environment_approval_current';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_require_environment_gate_before_lease
BEFORE UPDATE OF lifecycle ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_require_job_environment_gate_before_lease();

CREATE FUNCTION automata_require_secret_bindings_before_preparing()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    selected_count BIGINT;
    bound_count BIGINT;
    database_now_ms BIGINT;
BEGIN
    IF OLD.lifecycle <> 'leased' OR NEW.lifecycle <> 'preparing'
       OR NOT EXISTS (
           SELECT 1 FROM workflow_plan_v2_concrete_jobs WHERE job_id = NEW.job_id
       ) THEN
        RETURN NEW;
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT count(*) INTO selected_count
    FROM job_secret_selections WHERE attempt_id = NEW.id;
    SELECT count(*) INTO bound_count
    FROM job_secret_bindings AS binding
    JOIN secret_workload_grants AS workload_grant
      ON workload_grant.tenant_id = binding.tenant_id
     AND workload_grant.id = binding.grant_id
    WHERE binding.attempt_id = NEW.id
      AND binding.lease_id = NEW.lease_id
      AND binding.fencing_token = NEW.fencing_token
      AND workload_grant.status = 'active'
      AND workload_grant.lease_id = NEW.lease_id
      AND workload_grant.fencing_token = NEW.fencing_token
      AND database_now_ms < workload_grant.expires_at_ms;
    IF bound_count <> selected_count THEN
        RAISE EXCEPTION 'job cannot prepare before every selected secret is lease-bound'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_secret_bindings_complete';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_require_secret_bindings_before_preparing
BEFORE UPDATE OF lifecycle ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_require_secret_bindings_before_preparing();

CREATE FUNCTION automata_cancel_pending_environment_gate_for_attempt()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now_ms BIGINT;
BEGIN
    IF NEW.lifecycle NOT IN ('cancelled', 'timed_out')
       OR OLD.lifecycle = NEW.lifecycle THEN
        RETURN NEW;
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    UPDATE protected_environment_approval_requests AS request
    SET status = 'cancelled',
        resolved_at_ms = database_now_ms,
        resolution_reason = CASE
            WHEN environment.status = 'disabled' THEN 'environment_disabled'
            WHEN request.environment_revision <> environment.revision
              OR request.required_approvals <> environment.required_approvals
              OR request.prevent_self_review <> environment.prevent_self_review
              OR environment.protection_mode <> 'required_approvals'
                THEN 'policy_changed'
            ELSE 'workload_cancelled'
        END,
        revision = request.revision + 1
    FROM job_environment_gates AS gate
    JOIN repository_environments AS environment
      ON environment.tenant_id = gate.tenant_id
     AND environment.repository_id = gate.repository_id
     AND environment.id = gate.environment_id
    WHERE gate.attempt_id = NEW.id
      AND gate.approval_request_id = request.id
      AND request.status = 'pending';
    UPDATE job_environment_gates
    SET state = 'cancelled', updated_at_ms = database_now_ms,
        revision = revision + 1
    WHERE attempt_id = NEW.id
      AND state IN ('selection_pending', 'waiting', 'resolving');
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_cancel_pending_environment_gate
AFTER UPDATE OF lifecycle ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_cancel_pending_environment_gate_for_attempt();

CREATE FUNCTION automata_job_binding_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'job credential bindings are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'job_credential_bindings_append_only';
END;
$automata$;

CREATE TRIGGER job_variable_bindings_append_only
BEFORE UPDATE OR DELETE ON job_variable_bindings
FOR EACH ROW EXECUTE FUNCTION automata_job_binding_append_only();
CREATE TRIGGER job_missing_variable_bindings_append_only
BEFORE UPDATE OR DELETE ON job_missing_variable_bindings
FOR EACH ROW EXECUTE FUNCTION automata_job_binding_append_only();
CREATE TRIGGER job_secret_bindings_append_only
BEFORE UPDATE OR DELETE ON job_secret_bindings
FOR EACH ROW EXECUTE FUNCTION automata_job_binding_append_only();
CREATE TRIGGER job_secret_selections_append_only
BEFORE UPDATE OR DELETE ON job_secret_selections
FOR EACH ROW EXECUTE FUNCTION automata_job_binding_append_only();
CREATE TRIGGER job_missing_secret_bindings_append_only
BEFORE UPDATE OR DELETE ON job_missing_secret_bindings
FOR EACH ROW EXECUTE FUNCTION automata_job_binding_append_only();
