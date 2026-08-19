-- Runtime policy selection is no longer GitHub-manifest-exclusive. A common
-- provider connection may bind the same exact current policy by schema and
-- canonical digest, while the existing GitHub manifest pair remains valid.
CREATE OR REPLACE FUNCTION automata_require_current_manifest_runtime_policy_pair()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    pair_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM workflow_runtime_policy_current AS current_policy
        JOIN github_provider_manifest_current AS current_manifest
          ON current_manifest.tenant_id = current_policy.tenant_id
         AND current_manifest.repository_id = current_policy.repository_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = current_manifest.tenant_id
         AND manifest.repository_id = current_manifest.repository_id
         AND manifest.provider_connection_id = current_manifest.provider_connection_id
         AND manifest.manifest_revision = current_manifest.manifest_revision
         AND manifest.manifest_digest = current_manifest.manifest_digest
        WHERE current_policy.tenant_id = NEW.tenant_id
          AND current_policy.repository_id = NEW.repository_id
          AND manifest.runtime_policy_revision = current_policy.policy_revision
          AND manifest.runtime_policy_digest = current_policy.policy_digest
    ) OR EXISTS (
        SELECT 1
        FROM workflow_runtime_policy_current AS current_policy
        JOIN workflow_runtime_policy_revisions AS policy
          ON policy.tenant_id = current_policy.tenant_id
         AND policy.repository_id = current_policy.repository_id
         AND policy.policy_revision = current_policy.policy_revision
         AND policy.policy_digest = current_policy.policy_digest
         AND policy.state = 'sealed'
        JOIN repositories AS repository
          ON repository.tenant_id = current_policy.tenant_id
         AND repository.id = current_policy.repository_id
        JOIN provider_connection_revisions AS connection
          ON connection.workspace_id = repository.tenant_id
         AND connection.external_repository_id = repository.provider_repository_id
         AND connection.lifecycle_state = 'active'
         AND connection.runner_policy_schema = policy.policy_schema
         AND connection.runner_policy_digest = pg_catalog.sha256(policy.canonical_policy)
        JOIN provider_instance_revisions AS provider
          ON provider.instance_id = connection.provider_instance_id
         AND provider.revision = connection.provider_revision
         AND provider.provider_type = repository.scm_provider
         AND provider.configuration_digest = connection.provider_configuration_digest
         AND provider.capability_digest = connection.capability_digest
         AND provider.lifecycle_state = 'active'
        WHERE current_policy.tenant_id = NEW.tenant_id
          AND current_policy.repository_id = NEW.repository_id
    ) INTO pair_exists;
    IF pair_exists IS NOT TRUE THEN
        RAISE EXCEPTION 'current provider manifest and runtime policy are not an exact pair'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_current_runtime_policy_pair';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION automata_require_workflow_runtime_policy_pin_provenance()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1
    FROM provider_workflow_admission_evidence AS evidence
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = evidence.tenant_id
     AND policy.repository_id = evidence.repository_id
     AND policy.policy_revision = NEW.policy_revision
     AND policy.policy_digest = NEW.policy_digest
     AND policy.policy_schema = evidence.runner_policy_schema
     AND pg_catalog.sha256(policy.canonical_policy) = evidence.runner_policy_digest
     AND policy.state = 'sealed'
    JOIN workflow_runs AS run
      ON run.id = evidence.run_id AND run.repository_id = evidence.repository_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = evidence.run_id
    WHERE evidence.run_id = NEW.run_id
      AND evidence.tenant_id = NEW.tenant_id
      AND evidence.repository_id = NEW.repository_id
      AND evidence.admitted_at_ms = NEW.pinned_at_ms
    FOR SHARE OF evidence, policy, run, marker;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM github_workflow_run_manifest_origins AS origin
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = origin.tenant_id
     AND manifest.repository_id = origin.repository_id
     AND manifest.provider_connection_id = origin.provider_connection_id
     AND manifest.manifest_revision = origin.provider_manifest_revision
     AND manifest.manifest_digest = origin.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = manifest.tenant_id
     AND policy.repository_id = manifest.repository_id
     AND policy.policy_revision = manifest.runtime_policy_revision
     AND policy.policy_digest = manifest.runtime_policy_digest
     AND policy.state = 'sealed'
    JOIN workflow_runs AS run
      ON run.id = origin.run_id AND run.repository_id = origin.repository_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = origin.run_id
    WHERE origin.run_id = NEW.run_id
      AND origin.tenant_id = NEW.tenant_id
      AND origin.repository_id = NEW.repository_id
      AND origin.admitted_at_ms = NEW.pinned_at_ms
      AND manifest.runtime_policy_revision = NEW.policy_revision
      AND manifest.runtime_policy_digest = NEW.policy_digest
    FOR SHARE OF manifest, policy, run, marker;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_runs AS run
    JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
    JOIN security_audit_events AS audit
      ON audit.tenant_id = NEW.tenant_id
     AND audit.action = 'workflow.dispatch'
     AND audit.outcome = 'succeeded'
     AND audit.resource_kind = 'workflow_run'
     AND audit.resource_id = NEW.run_id::TEXT
     AND audit.occurred_at_ms = NEW.pinned_at_ms
     AND audit.actor_kind = 'human'
     AND audit.actor_principal_id IS NOT NULL
     AND (
          audit.actor_session_id IS NOT NULL
          OR EXISTS (
              SELECT 1 FROM delegated_actor_audit_evidence AS delegated
              WHERE delegated.event_id = audit.event_id
                AND delegated.tenant_id = audit.tenant_id
                AND delegated.principal_id = audit.actor_principal_id
                AND delegated.issued_at_ms <= audit.occurred_at_ms
                AND delegated.expires_at_ms > audit.occurred_at_ms
          )
     )
     AND audit.authorization_revision IS NOT NULL
    JOIN github_provider_manifest_current AS current_manifest
      ON current_manifest.tenant_id = NEW.tenant_id
     AND current_manifest.repository_id = NEW.repository_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = current_manifest.tenant_id
     AND manifest.repository_id = current_manifest.repository_id
     AND manifest.provider_connection_id = current_manifest.provider_connection_id
     AND manifest.manifest_revision = current_manifest.manifest_revision
     AND manifest.manifest_digest = current_manifest.manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = manifest.tenant_id
     AND policy.repository_id = manifest.repository_id
     AND policy.policy_revision = manifest.runtime_policy_revision
     AND policy.policy_digest = manifest.runtime_policy_digest
     AND policy.state = 'sealed'
    WHERE run.id = NEW.run_id
      AND run.repository_id = NEW.repository_id
      AND manifest.runtime_policy_revision = NEW.policy_revision
      AND manifest.runtime_policy_digest = NEW.policy_digest
    FOR SHARE OF run, marker, audit, current_manifest, manifest, policy;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow runtime policy pin lacks authenticated provider provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_runtime_policy_pin_provenance';
    END IF;
    RETURN NEW;
END;
$$;

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
      AND receipt.idempotency_key = evidence.delivery_id::TEXT
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

-- Immutable common-provider selection evidence recorded atomically with one
-- logical workflow admission. A later processing reclaim may authorize exact
-- replay, but can never replace the original normalized selection.
CREATE TABLE provider_workflow_admission_evidence (
    run_id UUID PRIMARY KEY REFERENCES workflow_runs (id) ON DELETE RESTRICT,
    delivery_id UUID NOT NULL REFERENCES provider_deliveries (delivery_id)
        ON DELETE RESTRICT,
    invocation_id UUID NOT NULL REFERENCES provider_processing_invocations (invocation_id)
        ON DELETE RESTRICT,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    workflow_id UUID NOT NULL,
    workflow_path TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    provider_instance_id UUID NOT NULL,
    provider_revision BIGINT NOT NULL,
    connection_id UUID NOT NULL,
    connection_revision BIGINT NOT NULL,
    provider_configuration_digest BYTEA NOT NULL,
    capability_digest BYTEA NOT NULL,
    runner_policy_schema SMALLINT NOT NULL,
    runner_policy_digest BYTEA NOT NULL,
    normalized_trigger_digest BYTEA NOT NULL,
    raw_event_digest BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    source_revision BYTEA NOT NULL,
    git_ref TEXT NOT NULL,
    event_name TEXT NOT NULL,
    actor TEXT,
    original_worker_id UUID NOT NULL,
    original_fence BIGINT NOT NULL,
    original_claimed_at_ms BIGINT NOT NULL,
    original_expires_at_ms BIGINT NOT NULL,
    admitted_at_ms BIGINT NOT NULL,
    FOREIGN KEY (connection_id, connection_revision)
        REFERENCES provider_connection_revisions (connection_id, revision)
        ON DELETE RESTRICT,
    CHECK (octet_length(tenant_id) BETWEEN 1 AND 255),
    CHECK (repository_id <> '00000000-0000-0000-0000-000000000000'::UUID),
    CHECK (workflow_id <> '00000000-0000-0000-0000-000000000000'::UUID),
    CHECK (
        octet_length(workflow_path) BETWEEN 1 AND 1024
        AND btrim(workflow_path) = workflow_path
        AND workflow_path !~ '[[:cntrl:]\\]'
        AND left(workflow_path, 1) <> '/'
        AND workflow_path !~ '(^|/)(\.|\.\.)(/|$)'
        AND workflow_path !~ '//'
    ),
    CHECK (octet_length(provider_type) BETWEEN 1 AND 64),
    CHECK (provider_revision > 0 AND connection_revision > 0),
    CHECK (octet_length(provider_configuration_digest) = 32),
    CHECK (octet_length(capability_digest) = 32),
    CHECK (runner_policy_schema > 0),
    CHECK (octet_length(runner_policy_digest) = 32),
    CHECK (octet_length(normalized_trigger_digest) = 32),
    CHECK (octet_length(raw_event_digest) = 32),
    CHECK (octet_length(request_digest) = 32),
    CHECK (octet_length(source_revision) IN (20, 32)),
    CHECK (
        octet_length(git_ref) BETWEEN 6 AND 1024
        AND git_ref LIKE 'refs/%' AND git_ref !~ '[[:cntrl:]]'
    ),
    CHECK (
        octet_length(event_name) BETWEEN 1 AND 128
        AND event_name !~ '[[:cntrl:]]'
    ),
    CHECK (actor IS NULL OR (
        octet_length(actor) BETWEEN 1 AND 1024 AND actor !~ '[[:cntrl:]]'
    )),
    CHECK (original_fence > 0),
    CHECK (original_claimed_at_ms >= 0),
    CHECK (original_expires_at_ms > original_claimed_at_ms),
    CHECK (admitted_at_ms >= original_claimed_at_ms),
    CHECK (admitted_at_ms < original_expires_at_ms)
);

CREATE FUNCTION automata_provider_workflow_admission_evidence_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'provider workflow admission evidence is immutable';
END;
$$;

CREATE TRIGGER provider_workflow_admission_evidence_no_update_delete
    BEFORE UPDATE OR DELETE ON provider_workflow_admission_evidence
    FOR EACH ROW EXECUTE FUNCTION automata_provider_workflow_admission_evidence_immutable();

CREATE TRIGGER provider_workflow_admission_evidence_no_truncate
    BEFORE TRUNCATE ON provider_workflow_admission_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION automata_provider_workflow_admission_evidence_immutable();

CREATE TABLE provider_result_subjects (
    subject_id UUID PRIMARY KEY,
    connection_id UUID NOT NULL,
    connection_revision BIGINT NOT NULL,
    connection_digest BYTEA NOT NULL,
    object_algorithm TEXT NOT NULL,
    object_bytes BYTEA NOT NULL,
    subject_kind TEXT NOT NULL,
    invocation_id UUID,
    workflow_path TEXT,
    run_id UUID,
    job_id UUID,
    attempt BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    subject_digest BYTEA NOT NULL,
    FOREIGN KEY (connection_id, connection_revision)
        REFERENCES provider_connection_revisions (connection_id, revision)
        ON DELETE RESTRICT,
    CHECK (connection_revision > 0),
    CHECK (octet_length(connection_digest) = 32),
    CHECK (
        (object_algorithm = 'sha1' AND octet_length(object_bytes) = 20)
        OR (object_algorithm = 'sha256' AND octet_length(object_bytes) = 32)
    ),
    CHECK (
        (subject_kind = 'workflow-invocation'
            AND invocation_id IS NOT NULL AND workflow_path IS NOT NULL
            AND run_id IS NULL AND job_id IS NULL)
        OR (subject_kind = 'workflow-run'
            AND invocation_id IS NULL AND workflow_path IS NULL
            AND run_id IS NOT NULL AND job_id IS NULL)
        OR (subject_kind = 'job'
            AND invocation_id IS NULL AND workflow_path IS NULL
            AND run_id IS NOT NULL AND job_id IS NOT NULL)
    ),
    CHECK (
        workflow_path IS NULL OR (
            octet_length(workflow_path) BETWEEN 1 AND 1024
            AND btrim(workflow_path) = workflow_path
            AND workflow_path !~ '[[:cntrl:]\\]'
            AND left(workflow_path, 1) <> '/'
            AND workflow_path !~ '(^|/)(\.|\.\.)(/|$)'
            AND workflow_path !~ '//'
        )
    ),
    CHECK (attempt BETWEEN 1 AND 4294967295),
    CHECK (created_at_ms >= 0),
    CHECK (octet_length(subject_digest) = 32)
);

CREATE TABLE provider_result_outbox (
    subject_id UUID PRIMARY KEY REFERENCES provider_result_subjects (subject_id)
        ON DELETE RESTRICT,
    generation BIGINT NOT NULL,
    phase TEXT NOT NULL,
    conclusion TEXT,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_url TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    desired_digest BYTEA NOT NULL,
    state TEXT NOT NULL,
    available_at_ms BIGINT NOT NULL,
    attempts SMALLINT NOT NULL DEFAULT 0,
    next_fence BIGINT NOT NULL DEFAULT 0,
    claim_worker_id UUID,
    claim_fence BIGINT,
    claim_started_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    publication_model TEXT,
    external_result_id TEXT,
    provider_state_digest BYTEA,
    publication_observed_at_ms BIGINT,
    publication_evidence_digest BYTEA,
    failed_at_ms BIGINT,
    failure_kind TEXT,
    UNIQUE (subject_id, generation),
    CHECK (generation > 0),
    CHECK (phase IN ('queued', 'running', 'completed')),
    CHECK (
        (phase = 'completed' AND conclusion IS NOT NULL AND conclusion IN (
            'success', 'failure', 'error', 'cancelled', 'skipped',
            'timed-out', 'neutral', 'action-required'
        )) OR (phase <> 'completed' AND conclusion IS NULL)
    ),
    CHECK (octet_length(title) BETWEEN 1 AND 255),
    CHECK (octet_length(summary) <= 65536),
    CHECK (octet_length(details_url) BETWEEN 1 AND 8192),
    CHECK (updated_at_ms >= 0),
    CHECK (octet_length(desired_digest) = 32),
    CHECK (state IN ('pending', 'claimed', 'completed', 'failed')),
    CHECK (available_at_ms >= updated_at_ms),
    CHECK (attempts BETWEEN 0 AND 64),
    CHECK (next_fence >= attempts),
    CHECK (
        (state = 'claimed'
            AND claim_worker_id IS NOT NULL AND claim_fence IS NOT NULL
            AND claim_started_at_ms IS NOT NULL AND claim_expires_at_ms IS NOT NULL
            AND claim_fence > 0 AND claim_started_at_ms >= 0
            AND claim_expires_at_ms > claim_started_at_ms
            AND claim_expires_at_ms - claim_started_at_ms <= 3600000)
        OR (state <> 'claimed'
            AND claim_worker_id IS NULL AND claim_fence IS NULL
            AND claim_started_at_ms IS NULL AND claim_expires_at_ms IS NULL)
    ),
    CHECK (
        (state = 'completed'
            AND publication_model IS NOT NULL
            AND publication_model IN ('mutable-rich-check', 'append-only-commit-status')
            AND provider_state_digest IS NOT NULL
            AND publication_observed_at_ms IS NOT NULL
            AND publication_observed_at_ms >= updated_at_ms
            AND publication_evidence_digest IS NOT NULL
            AND failed_at_ms IS NULL AND failure_kind IS NULL)
        OR (state <> 'completed'
            AND publication_model IS NULL AND external_result_id IS NULL
            AND provider_state_digest IS NULL AND publication_observed_at_ms IS NULL
            AND publication_evidence_digest IS NULL)
    ),
    CHECK (external_result_id IS NULL OR octet_length(external_result_id) BETWEEN 1 AND 512),
    CHECK (provider_state_digest IS NULL OR octet_length(provider_state_digest) = 32),
    CHECK (
        publication_evidence_digest IS NULL
        OR octet_length(publication_evidence_digest) = 32
    ),
    CHECK (
        (state = 'failed' AND failed_at_ms IS NOT NULL
            AND failure_kind IS NOT NULL AND failure_kind IN (
            'unsupported', 'unauthorized', 'forbidden', 'invalid-response',
            'conflict', 'attempt-limit'
        )) OR (state <> 'failed' AND failed_at_ms IS NULL AND failure_kind IS NULL)
    )
);

CREATE TABLE provider_result_annotations (
    subject_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    ordinal INTEGER NOT NULL,
    path TEXT NOT NULL,
    start_line BIGINT NOT NULL,
    end_line BIGINT NOT NULL,
    level TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY (subject_id, generation, ordinal),
    FOREIGN KEY (subject_id, generation)
        REFERENCES provider_result_outbox (subject_id, generation)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK (generation > 0),
    CHECK (ordinal BETWEEN 0 AND 4095),
    CHECK (
        octet_length(path) BETWEEN 1 AND 1024
        AND btrim(path) = path
        AND path !~ '[[:cntrl:]\\]'
        AND left(path, 1) <> '/'
        AND path !~ '(^|/)(\.|\.\.)(/|$)'
        AND path !~ '//'
    ),
    CHECK (start_line BETWEEN 1 AND 4294967295),
    CHECK (end_line BETWEEN start_line AND 4294967295),
    CHECK (level IN ('notice', 'warning', 'failure')),
    CHECK (octet_length(title) BETWEEN 1 AND 255),
    CHECK (octet_length(message) BETWEEN 1 AND 65536)
);

CREATE INDEX provider_result_claimable
    ON provider_result_outbox (available_at_ms, subject_id)
    WHERE state IN ('pending', 'claimed');

CREATE INDEX provider_result_subjects_by_connection
    ON provider_result_subjects (connection_id, subject_id);
