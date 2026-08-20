-- Provider-delivery admissions carry authenticated provider/manifest
-- provenance rather than GitHub subject-evidence rows.  The preparation
-- trigger already joins the exact manifest origin and sealed runtime policy;
-- requiring the separate subject-evidence flag here incorrectly rejects
-- provider-delivery workflow jobs at the first preparation claim.
CREATE OR REPLACE FUNCTION automata_require_preparation_runner_policy_provenance() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.runner_policy_digest IS DISTINCT FROM OLD.runner_policy_digest
            OR NEW.runner_policy_object_key IS DISTINCT FROM OLD.runner_policy_object_key
            OR NEW.runner_policy_size_bytes IS DISTINCT FROM OLD.runner_policy_size_bytes
            OR NEW.runner_policy_media_type IS DISTINCT FROM OLD.runner_policy_media_type
        THEN
            RAISE EXCEPTION 'logical preparation runner policy is immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_runner_policy_immutable';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM logical_workflow_jobs AS job
    JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = job.run_id
    JOIN github_workflow_run_manifest_origins AS origin
      ON origin.run_id = job.run_id
     AND origin.tenant_id = pin.tenant_id
     AND origin.repository_id = pin.repository_id
    JOIN workflow_admission_receipts AS receipt
      ON receipt.tenant_id = origin.tenant_id
     AND receipt.idempotency_kind = origin.admission_idempotency_kind
     AND receipt.idempotency_key = origin.admission_idempotency_key
     AND receipt.repository_id = origin.repository_id
     AND receipt.run_id = origin.run_id
     AND receipt.request_digest = origin.logical_admission_digest
     AND receipt.committed_at_ms = origin.admitted_at_ms
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = origin.tenant_id
     AND manifest.repository_id = origin.repository_id
     AND manifest.provider_connection_id = origin.provider_connection_id
     AND manifest.manifest_revision = origin.provider_manifest_revision
     AND manifest.manifest_digest = origin.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = pin.tenant_id
     AND policy.repository_id = pin.repository_id
     AND policy.policy_revision = pin.policy_revision
     AND policy.policy_digest = pin.policy_digest
     AND policy.state = 'sealed'
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
      AND NEW.runtime_policy_revision = pin.policy_revision
      AND NEW.runtime_policy_digest = pin.policy_digest
      AND manifest.runtime_policy_revision = pin.policy_revision
      AND manifest.runtime_policy_digest = pin.policy_digest
      AND NEW.runner_policy_digest = manifest.runner_policy_digest
      AND NEW.runner_policy_object_key = manifest.runner_policy_object_key
      AND NEW.runner_policy_size_bytes = manifest.runner_policy_size_bytes
      AND NEW.runner_policy_media_type = manifest.runner_policy_media_type
      AND NEW.runner_policy_digest = pg_catalog.sha256(policy.canonical_policy)
      AND NEW.runner_policy_size_bytes = pg_catalog.octet_length(policy.canonical_policy)
    FOR KEY SHARE OF job, pin, receipt, manifest, policy;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'logical preparation runner policy lacks authenticated manifest provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_runner_policy_provenance';
    END IF;
    RETURN NEW;
END;
$$;
