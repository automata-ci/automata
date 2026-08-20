-- Bind the workflow-namespaced provider idempotency key into immutable
-- admission evidence. Provider deliveries can select multiple workflow files,
-- so the receipt key intentionally differs from the bare delivery UUID.
ALTER TABLE provider_workflow_admission_evidence
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

DROP TRIGGER IF EXISTS provider_workflow_admission_evidence_no_update_delete
    ON provider_workflow_admission_evidence;

UPDATE provider_workflow_admission_evidence AS evidence
SET idempotency_key = receipt.idempotency_key
FROM workflow_admission_receipts AS receipt
WHERE receipt.run_id = evidence.run_id
  AND receipt.idempotency_kind = 'provider_delivery'
  AND receipt.request_digest = evidence.request_digest;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM provider_workflow_admission_evidence
        WHERE idempotency_key IS NULL
    ) THEN
        RAISE EXCEPTION 'provider admission evidence lacks its workflow idempotency key';
    END IF;
END;
$$;

ALTER TABLE provider_workflow_admission_evidence
    ALTER COLUMN idempotency_key SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint
        WHERE conrelid = 'provider_workflow_admission_evidence'::REGCLASS
          AND conname = 'provider_workflow_admission_evidence_idempotency_key_shape'
    ) THEN
        ALTER TABLE provider_workflow_admission_evidence
            ADD CONSTRAINT provider_workflow_admission_evidence_idempotency_key_shape
            CHECK (
                octet_length(idempotency_key) BETWEEN 1 AND 1024
                AND idempotency_key !~ '[[:cntrl:]]'
            );
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS provider_workflow_admission_evidence_no_update_delete
    ON provider_workflow_admission_evidence;
CREATE TRIGGER provider_workflow_admission_evidence_no_update_delete
    BEFORE UPDATE OR DELETE ON provider_workflow_admission_evidence
    FOR EACH ROW EXECUTE FUNCTION automata_provider_workflow_admission_evidence_immutable();

-- The common admission path is the source of truth for provider-delivery
-- executions.  Build the GitHub execution-origin projection from that
-- immutable evidence and the exact current adapter credentials; activation,
-- runner authority, and workload custody all consume this one projection.
-- Scheduled and rerun origins remain in the existing second branch below.
CREATE OR REPLACE VIEW github_workflow_run_base_manifest_origins AS
SELECT
    evidence.tenant_id,
    evidence.repository_id,
    evidence.workflow_id,
    run.snapshot_id,
    evidence.run_id,
    marker.root_invocation_id,
    'provider_delivery'::TEXT AS origin_kind,
    evidence.delivery_id AS origin_id,
    'provider_delivery'::TEXT AS admission_idempotency_kind,
    receipt.idempotency_key COLLATE pg_catalog."C" AS admission_idempotency_key,
    evidence.run_id AS github_check_subject_id,
    evidence.source_revision AS github_check_head_sha,
    evidence.workflow_path COLLATE pg_catalog."C",
    snapshot.source_digest,
    evidence.event_name COLLATE pg_catalog."C",
    run.event_digest,
    evidence.git_ref COLLATE pg_catalog."C",
    run.plan_schema::SMALLINT AS workflow_plan_schema,
    run.plan_digest,
    evidence.request_digest AS logical_admission_digest,
    evidence.admitted_at_ms,
    evidence.request_digest AS subject_evidence_sha256,
    evidence.connection_id AS provider_connection_id,
    manifest.provider_installation_id,
    manifest.github_repository_id,
    manifest.github_repository_owner_id,
    manifest.github_repository_name,
    manifest.repository_visibility,
    manifest.manifest_revision AS provider_manifest_revision,
    manifest.manifest_digest AS provider_manifest_digest,
    manifest.webhook_verifier_fingerprint_sha256
        AS authenticated_webhook_verifier_fingerprint_sha256,
    manifest.webhook_verifier_revision
        AS authenticated_webhook_verifier_revision,
    checks.id AS checks_authority_id,
    checks.identity_digest AS checks_authority_identity_digest,
    checks.app_configuration_revision
        AS checks_authority_app_configuration_revision,
    checks.policy_revision AS checks_authority_policy_revision,
    contents.id AS repository_contents_authority_id,
    contents.identity_digest AS repository_contents_authority_identity_digest,
    contents.app_configuration_revision
        AS repository_contents_authority_app_configuration_revision,
    contents.policy_revision AS repository_contents_authority_policy_revision
FROM provider_workflow_admission_evidence AS evidence
JOIN workflow_admission_receipts AS receipt
  ON receipt.run_id = evidence.run_id
 AND receipt.tenant_id = evidence.tenant_id
 AND receipt.repository_id = evidence.repository_id
 AND receipt.idempotency_kind = 'provider_delivery'
 AND receipt.request_digest = evidence.request_digest
 AND receipt.committed_at_ms = evidence.admitted_at_ms
JOIN workflow_runs AS run ON run.id = evidence.run_id
JOIN logical_workflow_runs AS marker ON marker.run_id = evidence.run_id
JOIN workflow_snapshots AS snapshot
  ON snapshot.id = run.snapshot_id
 AND snapshot.workflow_id = run.workflow_id
JOIN github_provider_manifest_current AS current_manifest
  ON current_manifest.tenant_id = evidence.tenant_id
 AND current_manifest.provider_connection_id = evidence.connection_id
JOIN github_provider_manifest_revisions AS manifest
  ON manifest.tenant_id = current_manifest.tenant_id
 AND manifest.repository_id = evidence.repository_id
 AND manifest.provider_connection_id = current_manifest.provider_connection_id
 AND manifest.manifest_revision = current_manifest.manifest_revision
 AND manifest.manifest_digest = current_manifest.manifest_digest
 AND manifest.runner_policy_digest = evidence.runner_policy_digest
 AND manifest.runtime_policy_revision = (
     SELECT pin.policy_revision
     FROM logical_workflow_runtime_policy_pins AS pin
     WHERE pin.run_id = evidence.run_id
 )
JOIN github_server_service_authorities AS checks
  ON checks.tenant_id = evidence.tenant_id
 AND checks.repository_id = evidence.repository_id
 AND checks.provider_connection_id = evidence.connection_id
 AND checks.provider_installation_id = manifest.provider_installation_id
 AND checks.github_repository_id = manifest.github_repository_id
 AND checks.github_repository_name = manifest.github_repository_name
 AND checks.service_scope = 'checks_write'
 AND checks.app_configuration_revision = manifest.app_configuration_revision
 AND checks.policy_revision = manifest.policy_revision
 AND checks.state = 'active'
JOIN github_server_service_authorities AS contents
  ON contents.tenant_id = evidence.tenant_id
 AND contents.repository_id = evidence.repository_id
 AND contents.provider_connection_id = evidence.connection_id
 AND contents.provider_installation_id = manifest.provider_installation_id
 AND contents.github_repository_id = manifest.github_repository_id
 AND contents.github_repository_name = manifest.github_repository_name
 AND contents.service_scope = 'repository_contents_read'
 AND contents.app_configuration_revision = manifest.app_configuration_revision
 AND contents.policy_revision = manifest.policy_revision
 AND contents.state = 'active'
WHERE evidence.provider_type = 'github';

CREATE OR REPLACE FUNCTION automata_require_open_workflow_admission_graph()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1
    FROM logical_workflow_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN provider_workflow_admission_evidence AS evidence
      ON evidence.run_id = marker.run_id
     AND evidence.request_digest = marker.admission_digest
    JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND receipt.idempotency_kind = 'provider_delivery'
      AND receipt.idempotency_key = evidence.idempotency_key
      AND receipt.request_digest = marker.admission_digest
      AND evidence.admitted_at_ms = receipt.committed_at_ms
      AND pin.pinned_at_ms = evidence.admitted_at_ms
    FOR KEY SHARE OF marker, receipt, evidence, pin;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM logical_workflow_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN github_workflow_run_manifest_origins AS origin
      ON origin.run_id = marker.run_id
     AND origin.root_invocation_id = marker.root_invocation_id
    JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND receipt.idempotency_kind = origin.admission_idempotency_kind
      AND receipt.idempotency_key = origin.admission_idempotency_key
      AND receipt.request_digest = marker.admission_digest
      AND origin.logical_admission_digest = marker.admission_digest
      AND origin.admitted_at_ms = receipt.committed_at_ms
      AND pin.pinned_at_ms = origin.admitted_at_ms
    FOR KEY SHARE OF marker, receipt, pin;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM logical_workflow_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    JOIN security_audit_events AS audit
      ON audit.tenant_id = pin.tenant_id
     AND audit.action = 'workflow.dispatch'
     AND audit.outcome = 'succeeded'
     AND audit.resource_kind = 'workflow_run'
     AND audit.resource_id = marker.run_id::TEXT
     AND audit.occurred_at_ms = pin.pinned_at_ms
     AND audit.actor_kind = 'human'
     AND audit.actor_principal_id IS NOT NULL
     AND audit.actor_session_id IS NOT NULL
     AND audit.authorization_revision IS NOT NULL
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND receipt.github_subject_evidence_required = FALSE
      AND receipt.request_digest = marker.admission_digest
      AND pin.pinned_at_ms = receipt.committed_at_ms
    FOR KEY SHARE OF marker, receipt, pin, audit;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM logical_workflow_reusable_call_publications AS publication
    JOIN logical_workflow_runs AS marker ON marker.run_id = publication.run_id
    WHERE publication.run_id = NEW.run_id
      AND publication.child_invocation_id = NEW.invocation_id
      AND publication.child_graph_sealed_at_ms IS NULL
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND marker.state IN ('pending', 'active')
      AND NOT EXISTS (
          SELECT 1 FROM logical_workflow_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR KEY SHARE OF publication, marker;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow graph insertion is outside an authenticated publication window'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_admission_graph_construction_window';
    END IF;
    RETURN NEW;
END;
$$;
