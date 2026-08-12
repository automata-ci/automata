-- Forward-only: replace the bounded 0069 precedence-only lease guard with a complete
-- database-time proof of the immutable protected-environment resolution and
-- every selected credential authority. Existing 0069 bytes remain immutable
-- so upgraded deployments retain SQLx checksum compatibility.

DROP TRIGGER job_attempts_require_current_secret_precedence_before_lease
    ON job_attempts;
DROP FUNCTION automata_require_current_secret_precedence_before_lease();

-- Missing bindings are immutable GitHub-compatible absence snapshots. A later
-- create must not inject a value into an already resolved job. Selected
-- authorities are different: every selected environment, approval, secret,
-- policy/access grant, and variable must still be exact and highest precedence
-- at the queued-to-leased database boundary.
CREATE FUNCTION automata_job_environment_gate_ready_authority_is_current(
    target_attempt_id UUID,
    target_now_ms BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
PARALLEL UNSAFE
AS $automata$
SELECT EXISTS (
    SELECT 1
    FROM job_environment_gates AS gate
    JOIN workflow_plan_v2_jobs AS logical_job
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
$automata$;

CREATE FUNCTION automata_require_current_job_environment_gate_before_lease()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now_ms BIGINT;
BEGIN
    IF OLD.lifecycle <> 'queued' OR NEW.lifecycle <> 'leased' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_concrete_jobs
        WHERE job_id = NEW.job_id
    ) THEN
        RETURN NEW;
    END IF;

    -- Parent-before-child SHARE locks conflict with every INSERT/UPDATE/DELETE
    -- of mutable authority while remaining compatible with ordinary readers.
    -- The following proof is a distinct statement, so READ COMMITTED observes
    -- every mutation that finished before these locks were obtained; the locks
    -- then hold the proved authority stable through lease commit.
    LOCK TABLE
        repository_environments,
        protected_environment_approval_requests,
        protected_environment_approval_decisions,
        repository_environment_reviewers,
        tenant_human_memberships,
        rbac_role_bindings,
        rbac_role_permissions,
        secrets,
        secret_policies,
        secret_repository_access,
        workflow_variables,
        workflow_variable_versions,
        workflow_plan_v2_reusable_invocation_expansions,
        workflow_plan_v2_reusable_secret_bindings
    IN SHARE MODE;

    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NOT automata_job_environment_gate_ready_authority_is_current(
        NEW.id,
        database_now_ms
    ) THEN
        RAISE EXCEPTION 'job environment and credential authority is no longer current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_environment_gate_ready_current';
    END IF;
    RETURN NEW;
END;
$automata$;

-- PostgreSQL fires same-event triggers in name order. The 00 variable-custody
-- guard runs first, this complete currentness proof runs second, and the older
-- 0064 shape/digest guard remains an independent final backstop afterward.
CREATE TRIGGER job_attempts_01_require_current_environment_gate_before_lease
BEFORE UPDATE OF lifecycle ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_require_current_job_environment_gate_before_lease();
