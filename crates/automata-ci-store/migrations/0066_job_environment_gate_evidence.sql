-- Value-free activation evidence for deterministic pre-lease environment gates.

-- A pre-0066 activation instance has no authenticated event/environment
-- evidence from which the current gate input can be reconstructed. Serialize
-- the cut against both facts that decide whether such state is live, then
-- refuse only nonempty active publications. Terminal history is inert and an
-- active zero-instance publication has no per-instance evidence to recover.
LOCK TABLE workflow_runs, workflow_plan_v2_instances
    IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_instances AS instance
        JOIN workflow_runs AS run ON run.id = instance.run_id
        WHERE run.status IN ('queued', 'in_progress')
    ) THEN
        RAISE EXCEPTION 'job environment evidence upgrade requires drained active legacy activation instances'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_environment_evidence_active_legacy_instances';
    END IF;
END;
$automata$;

CREATE TABLE workflow_plan_v2_job_environment_evidence (
    instance_id UUID PRIMARY KEY
        REFERENCES workflow_plan_v2_instances(id) ON DELETE CASCADE,
    environment_normalized_name TEXT COLLATE "C",
    event_trust TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    reusable_secret_permission TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT job_environment_evidence_environment CHECK (
        environment_normalized_name IS NULL
        OR (
            octet_length(environment_normalized_name) BETWEEN 1 AND 255
            AND environment_normalized_name = lower(environment_normalized_name)
            AND environment_normalized_name !~ '[[:cntrl:]]'
            AND btrim(environment_normalized_name) = environment_normalized_name
        )
    ),
    CONSTRAINT job_environment_evidence_event_trust CHECK (
        event_trust IN ('trusted', 'untrusted')
    ),
    CONSTRAINT job_environment_evidence_source_kind CHECK (
        source_kind IN ('same_repository', 'fork', 'dependabot')
    ),
    CONSTRAINT job_environment_evidence_source_trust CHECK (
        source_kind = 'same_repository' OR event_trust = 'untrusted'
    ),
    CONSTRAINT job_environment_evidence_reusable_permission CHECK (
        reusable_secret_permission IN ('none', 'explicit')
    ),
    CONSTRAINT job_environment_evidence_created_at CHECK (created_at_ms >= 0)
);

-- Reusable secret identifiers are GitHub-style case-insensitive names, while
-- the expansion ledger preserves source spelling. Refuse unsafe/colliding
-- historical targets, then compare their ASCII-uppercase canonical form to
-- job credential references and managed-secret names.
ALTER TABLE workflow_plan_v2_reusable_secret_bindings
    ADD CONSTRAINT workflow_plan_v2_reusable_secret_targets_canonicalizable CHECK (
        target_name ~ '^[A-Za-z_][A-Za-z0-9_]*$'
        AND upper(target_name) !~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'
        AND octet_length(target_name) <= 255
    );

CREATE UNIQUE INDEX workflow_plan_v2_reusable_secret_targets_casefold_unique
    ON workflow_plan_v2_reusable_secret_bindings (
        run_id, invocation_id, (upper(target_name) COLLATE "C")
    );

CREATE FUNCTION automata_validate_job_environment_activation_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    instance workflow_plan_v2_instances%ROWTYPE;
    logical_job workflow_plan_v2_jobs%ROWTYPE;
    root_invocation UUID;
    all_reusable_secret_references_bound BOOLEAN;
BEGIN
    SELECT * INTO STRICT instance
    FROM workflow_plan_v2_instances
    WHERE id = NEW.instance_id
    FOR SHARE;
    SELECT * INTO STRICT logical_job
    FROM workflow_plan_v2_jobs
    WHERE run_id = instance.run_id
      AND invocation_id = instance.invocation_id
      AND id = instance.logical_job_id
    FOR SHARE;
    SELECT marker.root_invocation_id INTO STRICT root_invocation
    FROM workflow_plan_v2_runs AS marker
    WHERE marker.run_id = instance.run_id
    FOR SHARE;
    SELECT NOT EXISTS (
        SELECT 1
        FROM unnest(logical_job.secret_reference_names) AS referenced_secret(name)
        WHERE NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_reusable_secret_bindings AS binding
            WHERE binding.run_id = instance.run_id
              AND binding.invocation_id = instance.invocation_id
              AND upper(binding.target_name) = referenced_secret.name
        )
    ) INTO all_reusable_secret_references_bound;

    IF NEW.created_at_ms <> instance.created_at_ms
       OR logical_job.environment_requirement_kind = 'unclassified'
       OR (
           logical_job.environment_requirement_kind = 'environment'
           AND NEW.environment_normalized_name IS NULL
       )
       OR (
           logical_job.environment_requirement_kind = 'none'
           AND NEW.environment_normalized_name IS NOT NULL
       )
       OR (
           instance.invocation_id = root_invocation
           AND NEW.reusable_secret_permission <> 'none'
       )
       OR (
           instance.invocation_id <> root_invocation
           AND cardinality(logical_job.secret_reference_names) > 0
           AND (
               NOT all_reusable_secret_references_bound
               OR NEW.reusable_secret_permission <> 'explicit'
           )
       )
       OR (
           instance.invocation_id <> root_invocation
           AND cardinality(logical_job.secret_reference_names) = 0
           AND NEW.reusable_secret_permission <> 'none'
       ) THEN
        RAISE EXCEPTION 'activation environment evidence is not exact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_environment_evidence_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_environment_evidence_validate
BEFORE INSERT ON workflow_plan_v2_job_environment_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_validate_job_environment_activation_evidence();

-- Reusable permission is name-specific. An unrelated forwarded secret must
-- never authorize selection of another repository/environment/tenant secret.
CREATE OR REPLACE FUNCTION automata_secret_is_available_to_gate(
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
   AND (
       (target_gate).invocation_kind = 'direct'
       OR (
           (target_gate).reusable_secret_permission = 'explicit'
           AND (target_policy).reusable_workflow_mode = 'explicit_only'
           AND EXISTS (
               SELECT 1
               FROM workflow_plan_v2_reusable_secret_bindings AS binding
               WHERE binding.run_id = (target_gate).run_id
                 AND binding.invocation_id = (target_gate).invocation_id
                 AND upper(binding.target_name) = (target_secret).canonical_name
           )
       )
   )
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

-- Variable values do not yet have an ephemeral, receipt-bound custody path.
-- Keep every variable-bearing logical job queued even if an older or direct
-- caller manages to move its credential gate to `ready`. A later migration
-- may replace this function only after it can prove an exact custody receipt.
CREATE FUNCTION automata_reject_job_variable_lease_without_custody()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.lifecycle = 'queued'
       AND NEW.lifecycle = 'leased'
       AND EXISTS (
           SELECT 1
           FROM workflow_plan_v2_concrete_jobs AS concrete
           JOIN workflow_plan_v2_jobs AS logical_job
             ON logical_job.run_id = concrete.run_id
            AND logical_job.invocation_id = concrete.invocation_id
            AND logical_job.id = concrete.logical_job_id
           WHERE concrete.job_id = NEW.job_id
             AND cardinality(logical_job.variable_reference_names) > 0
       ) THEN
        RAISE EXCEPTION 'variable-bearing jobs require an exact custody receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_variable_custody_required';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_00_require_variable_custody_before_lease
BEFORE UPDATE ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_reject_job_variable_lease_without_custody();

CREATE FUNCTION automata_reject_job_environment_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'activation environment evidence is append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'job_environment_evidence_append_only';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_environment_evidence_append_only
BEFORE UPDATE OR DELETE ON workflow_plan_v2_job_environment_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_reject_job_environment_evidence_mutation();

CREATE TRIGGER workflow_plan_v2_job_environment_evidence_no_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_environment_evidence
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_job_environment_evidence_mutation();
