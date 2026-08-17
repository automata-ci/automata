-- Durable manual-dispatch source resolution and exact replay fencing.
ALTER TABLE github_server_service_authority_handoffs
    DROP CONSTRAINT github_server_service_handoffs_action;

ALTER TABLE github_server_service_authority_handoffs
    ADD CONSTRAINT github_server_service_handoffs_action CHECK (
        consumer_action = ANY (ARRAY[
            'ensure_check_suite'::text,
            'create_check_run'::text,
            'reconcile_check_run'::text,
            'publish_check_run'::text,
            'fetch_private_repository_revision'::text,
            'fetch_private_repository_changed_files'::text,
            'discover_private_repository_schedules'::text,
            'observe_workflow_permission_defaults'::text,
            'fetch_private_pull_request_files'::text,
            'resolve_workflow_dispatch_source'::text
        ])
    );

CREATE TABLE workflow_dispatch_source_resolutions (
    tenant_id text NOT NULL,
    operation_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    workflow_path text NOT NULL COLLATE pg_catalog."C",
    git_ref text NOT NULL COLLATE pg_catalog."C",
    scm_provider text NOT NULL COLLATE pg_catalog."C",
    provider_repository_id text NOT NULL COLLATE pg_catalog."C",
    repository_owner text NOT NULL COLLATE pg_catalog."C",
    repository_name text NOT NULL COLLATE pg_catalog."C",
    github_repository_owner_id bigint NOT NULL,
    provider_connection_id uuid NOT NULL,
    provider_manifest_revision bigint NOT NULL,
    provider_manifest_digest bytea NOT NULL,
    private_source_authority_id uuid,
    private_source_authority_identity_digest bytea,
    private_source_authority_app_configuration_revision bigint,
    private_source_authority_policy_revision bigint,
    state text NOT NULL DEFAULT 'claimed' COLLATE pg_catalog."C",
    claim_owner_id uuid,
    claim_fence bigint NOT NULL DEFAULT 1,
    claimed_at_ms bigint,
    claim_expires_at_ms bigint,
    commit_sha bytea,
    source_digest bytea,
    source_object_key text COLLATE pg_catalog."C",
    source_size_bytes bigint,
    source_media_type text COLLATE pg_catalog."C",
    created_at_ms bigint NOT NULL,
    resolved_at_ms bigint,
    CONSTRAINT workflow_dispatch_source_resolutions_pkey
        PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT workflow_dispatch_source_resolutions_operation_non_nil CHECK (
        operation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_dispatch_source_resolutions_text_shape CHECK (
        scm_provider = 'github'
        AND octet_length(workflow_path) BETWEEN 1 AND 1024
        AND workflow_path !~ '[[:cntrl:]]'
        AND automata_github_provider_git_ref_canonical(git_ref)
        AND octet_length(provider_repository_id) BETWEEN 1 AND 1024
        AND octet_length(repository_owner) BETWEEN 1 AND 1024
        AND octet_length(repository_name) BETWEEN 1 AND 1024
    ),
    CONSTRAINT workflow_dispatch_source_resolutions_manifest_shape CHECK (
        provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND provider_manifest_revision > 0
        AND octet_length(provider_manifest_digest) = 32
        AND github_repository_owner_id > 0
    ),
    CONSTRAINT workflow_dispatch_source_resolutions_authority_shape CHECK (
        (private_source_authority_id IS NULL
            AND private_source_authority_identity_digest IS NULL
            AND private_source_authority_app_configuration_revision IS NULL
            AND private_source_authority_policy_revision IS NULL)
        OR
        (private_source_authority_id IS NOT NULL
            AND private_source_authority_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND octet_length(private_source_authority_identity_digest) = 32
            AND private_source_authority_app_configuration_revision > 0
            AND private_source_authority_policy_revision > 0)
    ),
    CONSTRAINT workflow_dispatch_source_resolutions_state CHECK (
        state = ANY (ARRAY['claimed'::text, 'retryable'::text, 'resolved'::text])
    ),
    CONSTRAINT workflow_dispatch_source_resolutions_state_shape CHECK (
        (state = 'claimed'
            AND claim_owner_id IS NOT NULL
            AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND claim_fence > 0
            AND claimed_at_ms >= created_at_ms
            AND claim_expires_at_ms > claimed_at_ms
            AND claim_expires_at_ms - claimed_at_ms <= 900000
            AND commit_sha IS NULL
            AND source_digest IS NULL
            AND source_object_key IS NULL
            AND source_size_bytes IS NULL
            AND source_media_type IS NULL
            AND resolved_at_ms IS NULL)
        OR
        (state = 'retryable'
            AND claim_owner_id IS NULL
            AND claim_fence > 0
            AND claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND commit_sha IS NULL
            AND source_digest IS NULL
            AND source_object_key IS NULL
            AND source_size_bytes IS NULL
            AND source_media_type IS NULL
            AND resolved_at_ms IS NULL)
        OR
        (state = 'resolved'
            AND claim_owner_id IS NULL
            AND claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND octet_length(commit_sha) IN (20, 32)
            AND octet_length(source_digest) = 32
            AND octet_length(source_object_key) BETWEEN 1 AND 1024
            AND source_object_key !~ '[[:cntrl:]]'
            AND source_size_bytes BETWEEN 1 AND 524288
            AND source_media_type = 'application/vnd.github-actions.workflow+yaml'
            AND resolved_at_ms >= created_at_ms)
    ),
    CONSTRAINT workflow_dispatch_source_resolutions_repository_fk
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_dispatch_source_resolutions_workflow_fk
        FOREIGN KEY (repository_id, workflow_id)
        REFERENCES workflow_definitions (repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_dispatch_source_resolutions_membership_fk
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES tenant_human_memberships (tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_dispatch_source_resolutions_manifest_fk
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            provider_manifest_revision, provider_manifest_digest
        ) REFERENCES github_provider_manifest_revisions (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_dispatch_source_resolutions_private_authority_fk
        FOREIGN KEY (tenant_id, private_source_authority_id)
        REFERENCES github_server_service_authorities (tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX workflow_dispatch_source_resolutions_live_claims
    ON workflow_dispatch_source_resolutions (claim_expires_at_ms)
    WHERE state = 'claimed';

CREATE TABLE delegated_actor_audit_evidence (
    event_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    principal_id uuid NOT NULL,
    issuer text NOT NULL,
    subject uuid NOT NULL,
    external_session_id uuid NOT NULL,
    assertion_id uuid NOT NULL,
    authenticated_at_ms bigint NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    CONSTRAINT delegated_actor_audit_evidence_assertion_unique
        UNIQUE (issuer, assertion_id),
    CONSTRAINT delegated_actor_audit_evidence_ids_non_nil CHECK (
        event_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND principal_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND subject <> '00000000-0000-0000-0000-000000000000'::uuid
        AND external_session_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND assertion_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT delegated_actor_audit_evidence_issuer_shape CHECK (
        octet_length(issuer) BETWEEN 9 AND 2048
        AND issuer ~ '^https://'
        AND issuer !~ '[[:cntrl:][:space:]]'
    ),
    CONSTRAINT delegated_actor_audit_evidence_time_shape CHECK (
        authenticated_at_ms >= 0
        AND authenticated_at_ms <= issued_at_ms
        AND issued_at_ms < expires_at_ms
        AND expires_at_ms - issued_at_ms <= 300000
    ),
    CONSTRAINT delegated_actor_audit_evidence_event_fk
        FOREIGN KEY (event_id) REFERENCES security_audit_events(event_id) ON DELETE RESTRICT,
    CONSTRAINT delegated_actor_audit_evidence_identity_fk
        FOREIGN KEY (issuer, subject, principal_id)
        REFERENCES delegated_actor_identities(issuer, subject, principal_id) ON DELETE RESTRICT,
    CONSTRAINT delegated_actor_audit_evidence_membership_fk
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE FUNCTION automata_reject_delegated_actor_audit_evidence_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'delegated actor audit evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'delegated_actor_audit_evidence_immutable';
END;
$$;

CREATE FUNCTION automata_validate_delegated_actor_audit_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM 1
    FROM security_audit_events AS audit
    WHERE audit.event_id = NEW.event_id
      AND audit.tenant_id = NEW.tenant_id
      AND audit.actor_kind = 'human'
      AND audit.actor_principal_id = NEW.principal_id
      AND audit.actor_session_id IS NULL
      AND audit.authorization_revision IS NOT NULL
      AND audit.action = 'workflow.dispatch'
      AND audit.outcome = 'succeeded'
      AND audit.resource_kind = 'workflow_run'
      AND audit.resource_id IS NOT NULL
      AND NEW.issued_at_ms <= audit.occurred_at_ms
      AND NEW.expires_at_ms > audit.occurred_at_ms
    FOR KEY SHARE OF audit;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'delegated actor audit evidence does not match its workflow dispatch'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'delegated_actor_audit_evidence_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER delegated_actor_audit_evidence_00_insert_guard
BEFORE INSERT ON delegated_actor_audit_evidence
FOR EACH ROW EXECUTE FUNCTION automata_validate_delegated_actor_audit_evidence();

CREATE TRIGGER delegated_actor_audit_evidence_no_update_delete
BEFORE UPDATE OR DELETE ON delegated_actor_audit_evidence
FOR EACH ROW EXECUTE FUNCTION automata_reject_delegated_actor_audit_evidence_mutation();

CREATE TRIGGER delegated_actor_audit_evidence_no_truncate
BEFORE TRUNCATE ON delegated_actor_audit_evidence
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_delegated_actor_audit_evidence_mutation();

CREATE OR REPLACE FUNCTION automata_require_open_workflow_admission_graph() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
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

CREATE OR REPLACE FUNCTION automata_require_workflow_runtime_policy_pin_provenance() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
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
      ON run.id = origin.run_id
     AND run.repository_id = origin.repository_id
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
        RAISE EXCEPTION 'workflow runtime policy pin lacks authenticated manifest provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_runtime_policy_pin_provenance';
    END IF;
    RETURN NEW;
END;
$$;
