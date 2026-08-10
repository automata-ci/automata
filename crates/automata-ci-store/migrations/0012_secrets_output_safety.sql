-- Pluggable secret persistence, protected environments, exact workload grants,
-- and fail-private publication-safety snapshots. Migration 0011 is reserved
-- for production dashboard metadata and intentionally owned by another lane.

-- Migration 0010 represented requested public log/artifact output as
-- `public_if_safe`. The shared policy domain now stores the configured request
-- as `public`; immutable attempt/artifact safety snapshots apply the hard cap.
UPDATE repository_publication_policies
SET log_audience = 'public'
WHERE log_audience = 'public_if_safe';

UPDATE repository_publication_policies
SET artifact_audience = 'public'
WHERE artifact_audience = 'public_if_safe';

ALTER TABLE repository_publication_policies
    DROP CONSTRAINT repository_publication_policies_log_audience,
    DROP CONSTRAINT repository_publication_policies_artifact_audience,
    ADD CONSTRAINT repository_publication_policies_log_audience CHECK (
        log_audience IN ('private', 'authenticated', 'public')
    ),
    ADD CONSTRAINT repository_publication_policies_artifact_audience CHECK (
        artifact_audience IN ('private', 'authenticated', 'public')
    );

-- A run snapshots the independently configured repository audiences. Existing
-- runs are deliberately not inferred from current repository settings.
ALTER TABLE workflow_runs
    ADD COLUMN publication_policy_revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN requested_dashboard_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN effective_dashboard_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN requested_log_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN requested_artifact_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN publication_safety_reason TEXT NOT NULL DEFAULT 'legacy_restricted',
    ADD COLUMN publication_safety_schema INTEGER NOT NULL DEFAULT 1,
    ADD CONSTRAINT workflow_runs_publication_policy_revision_positive CHECK (
        publication_policy_revision > 0
    ),
    ADD CONSTRAINT workflow_runs_requested_visibility CHECK (
        requested_dashboard_visibility IN ('private', 'authenticated', 'public')
        AND requested_log_visibility IN ('private', 'authenticated', 'public')
        AND requested_artifact_visibility IN ('private', 'authenticated', 'public')
    ),
    ADD CONSTRAINT workflow_runs_effective_dashboard_visibility CHECK (
        effective_dashboard_visibility IN ('private', 'authenticated', 'public')
    ),
    ADD CONSTRAINT workflow_runs_dashboard_visibility_cap CHECK (
        effective_dashboard_visibility = 'private'
        OR (
            effective_dashboard_visibility = 'authenticated'
            AND requested_dashboard_visibility IN ('authenticated', 'public')
        )
        OR (
            effective_dashboard_visibility = 'public'
            AND requested_dashboard_visibility = 'public'
        )
    ),
    ADD CONSTRAINT workflow_runs_publication_safety_reason_code CHECK (
        publication_safety_reason IN (
            'legacy_restricted', 'repository_policy', 'secret_exposure',
            'missing_policy', 'unsupported_policy_schema',
            'administrative_restriction'
        )
    ),
    ADD CONSTRAINT workflow_runs_publication_safety_schema CHECK (
        publication_safety_schema = 1
    );

CREATE FUNCTION automata_workflow_run_publication_snapshot_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.publication_policy_revision IS DISTINCT FROM OLD.publication_policy_revision
       OR NEW.requested_dashboard_visibility IS DISTINCT FROM OLD.requested_dashboard_visibility
       OR NEW.effective_dashboard_visibility IS DISTINCT FROM OLD.effective_dashboard_visibility
       OR NEW.requested_log_visibility IS DISTINCT FROM OLD.requested_log_visibility
       OR NEW.requested_artifact_visibility IS DISTINCT FROM OLD.requested_artifact_visibility
       OR NEW.publication_safety_reason IS DISTINCT FROM OLD.publication_safety_reason
       OR NEW.publication_safety_schema IS DISTINCT FROM OLD.publication_safety_schema THEN
        RAISE EXCEPTION 'workflow run publication snapshots are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_runs_publication_snapshot_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_publication_snapshot_immutable
BEFORE UPDATE ON workflow_runs
FOR EACH ROW
EXECUTE FUNCTION automata_workflow_run_publication_snapshot_immutable();

-- Unknown legacy and newly unclassified attempts use the most restrictive
-- class. New admission must supply its classification in the initial INSERT;
-- a defaulted attempt intentionally stays restricted for its whole lifetime.
ALTER TABLE job_attempts
    ADD COLUMN secret_exposure_class TEXT NOT NULL DEFAULT 'readable_secret',
    ADD COLUMN raw_log_disposition TEXT NOT NULL DEFAULT 'suppress_user_output',
    ADD COLUMN requested_log_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN effective_log_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN output_safety_reason TEXT NOT NULL DEFAULT 'legacy_restricted',
    ADD COLUMN output_safety_schema INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN classified_at_ms BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT job_attempts_secret_exposure_class CHECK (
        secret_exposure_class IN ('secretless', 'capability_only', 'readable_secret')
    ),
    ADD CONSTRAINT job_attempts_raw_log_disposition CHECK (
        raw_log_disposition IN ('persist', 'suppress_user_output')
    ),
    ADD CONSTRAINT job_attempts_log_visibility CHECK (
        requested_log_visibility IN ('private', 'authenticated', 'public')
        AND effective_log_visibility IN ('private', 'authenticated', 'public')
    ),
    ADD CONSTRAINT job_attempts_log_visibility_cap CHECK (
        effective_log_visibility = 'private'
        OR (
            effective_log_visibility = 'authenticated'
            AND requested_log_visibility IN ('authenticated', 'public')
        )
        OR (
            effective_log_visibility = 'public'
            AND requested_log_visibility = 'public'
        )
    ),
    ADD CONSTRAINT job_attempts_exposure_safety CHECK (
        (
            secret_exposure_class IN ('secretless', 'capability_only')
            AND raw_log_disposition = 'persist'
        ) OR (
            secret_exposure_class = 'readable_secret'
            AND raw_log_disposition = 'suppress_user_output'
            AND effective_log_visibility = 'private'
        )
    ),
    ADD CONSTRAINT job_attempts_output_safety_reason_code CHECK (
        output_safety_reason IN (
            'legacy_restricted', 'repository_policy', 'secret_exposure',
            'missing_policy', 'unsupported_policy_schema',
            'administrative_restriction'
        )
    ),
    ADD CONSTRAINT job_attempts_output_safety_schema CHECK (output_safety_schema = 1),
    ADD CONSTRAINT job_attempts_classification_time_nonnegative CHECK (
        classified_at_ms >= 0
    );

-- Attempt admission fixes the maximum secret exposure and output audience for
-- the attempt's lifetime. In particular, a readable-secret attempt cannot be
-- relabelled secretless after a workload grant has been issued.
CREATE FUNCTION automata_job_attempt_output_safety_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.secret_exposure_class IS DISTINCT FROM OLD.secret_exposure_class
       OR NEW.raw_log_disposition IS DISTINCT FROM OLD.raw_log_disposition
       OR NEW.requested_log_visibility IS DISTINCT FROM OLD.requested_log_visibility
       OR NEW.effective_log_visibility IS DISTINCT FROM OLD.effective_log_visibility
       OR NEW.output_safety_reason IS DISTINCT FROM OLD.output_safety_reason
       OR NEW.output_safety_schema IS DISTINCT FROM OLD.output_safety_schema
       OR NEW.classified_at_ms IS DISTINCT FROM OLD.classified_at_ms THEN
        RAISE EXCEPTION 'job attempt output safety snapshots are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'job_attempts_output_safety_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_output_safety_immutable
BEFORE UPDATE ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_job_attempt_output_safety_immutable();

ALTER TABLE attempt_log_streams
    ADD COLUMN secret_exposure_class TEXT NOT NULL DEFAULT 'readable_secret',
    ADD COLUMN raw_log_disposition TEXT NOT NULL DEFAULT 'suppress_user_output',
    ADD COLUMN requested_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN effective_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN output_safety_reason TEXT NOT NULL DEFAULT 'legacy_restricted',
    ADD COLUMN output_safety_schema INTEGER NOT NULL DEFAULT 1,
    ADD CONSTRAINT attempt_log_streams_secret_exposure_class CHECK (
        secret_exposure_class IN ('secretless', 'capability_only', 'readable_secret')
    ),
    ADD CONSTRAINT attempt_log_streams_raw_log_disposition CHECK (
        raw_log_disposition IN ('persist', 'suppress_user_output')
    ),
    ADD CONSTRAINT attempt_log_streams_visibility CHECK (
        requested_visibility IN ('private', 'authenticated', 'public')
        AND effective_visibility IN ('private', 'authenticated', 'public')
    ),
    ADD CONSTRAINT attempt_log_streams_visibility_cap CHECK (
        effective_visibility = 'private'
        OR (
            effective_visibility = 'authenticated'
            AND requested_visibility IN ('authenticated', 'public')
        )
        OR (
            effective_visibility = 'public'
            AND requested_visibility = 'public'
        )
    ),
    ADD CONSTRAINT attempt_log_streams_exposure_safety CHECK (
        (
            secret_exposure_class IN ('secretless', 'capability_only')
            AND raw_log_disposition = 'persist'
        ) OR (
            secret_exposure_class = 'readable_secret'
            AND raw_log_disposition = 'suppress_user_output'
            AND effective_visibility = 'private'
        )
    ),
    ADD CONSTRAINT attempt_log_streams_output_safety_reason_code CHECK (
        output_safety_reason IN (
            'legacy_restricted', 'repository_policy', 'secret_exposure',
            'missing_policy', 'unsupported_policy_schema',
            'administrative_restriction'
        )
    ),
    ADD CONSTRAINT attempt_log_streams_output_safety_schema CHECK (
        output_safety_schema = 1
    );

ALTER TABLE workflow_artifacts
    ADD COLUMN secret_exposure_class TEXT NOT NULL DEFAULT 'readable_secret',
    ADD COLUMN requested_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN effective_visibility TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN publication_safety_reason TEXT NOT NULL DEFAULT 'legacy_restricted',
    ADD COLUMN publication_safety_schema INTEGER NOT NULL DEFAULT 1,
    ADD CONSTRAINT workflow_artifacts_secret_exposure_class CHECK (
        secret_exposure_class IN ('secretless', 'capability_only', 'readable_secret')
    ),
    ADD CONSTRAINT workflow_artifacts_visibility CHECK (
        requested_visibility IN ('private', 'authenticated', 'public')
        AND effective_visibility IN ('private', 'authenticated', 'public')
    ),
    ADD CONSTRAINT workflow_artifacts_visibility_cap CHECK (
        effective_visibility = 'private'
        OR (
            effective_visibility = 'authenticated'
            AND requested_visibility IN ('authenticated', 'public')
        )
        OR (
            effective_visibility = 'public'
            AND requested_visibility = 'public'
        )
    ),
    ADD CONSTRAINT workflow_artifacts_exposure_safety CHECK (
        secret_exposure_class <> 'readable_secret'
        OR effective_visibility = 'private'
    ),
    ADD CONSTRAINT workflow_artifacts_publication_safety_reason_code CHECK (
        publication_safety_reason IN (
            'legacy_restricted', 'repository_policy', 'secret_exposure',
            'missing_policy', 'unsupported_policy_schema',
            'administrative_restriction'
        )
    ),
    ADD CONSTRAINT workflow_artifacts_publication_safety_schema CHECK (
        publication_safety_schema = 1
    );

-- Stream rows are a durable copy of their immutable attempt ceiling, not a
-- second classification input that an ingress path may claim independently.
CREATE FUNCTION automata_validate_attempt_log_safety_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    attempt_exposure TEXT;
    attempt_raw_disposition TEXT;
    attempt_requested_visibility TEXT;
    attempt_effective_visibility TEXT;
    attempt_reason TEXT;
    attempt_schema INTEGER;
BEGIN
    SELECT
        secret_exposure_class,
        raw_log_disposition,
        requested_log_visibility,
        effective_log_visibility,
        output_safety_reason,
        output_safety_schema
    INTO
        attempt_exposure,
        attempt_raw_disposition,
        attempt_requested_visibility,
        attempt_effective_visibility,
        attempt_reason,
        attempt_schema
    FROM job_attempts
    WHERE id = NEW.attempt_id;

    -- Preserve the existing foreign-key error for a nonexistent attempt.
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF NEW.secret_exposure_class IS DISTINCT FROM attempt_exposure
       OR NEW.raw_log_disposition IS DISTINCT FROM attempt_raw_disposition
       OR NEW.requested_visibility IS DISTINCT FROM attempt_requested_visibility
       OR NEW.effective_visibility IS DISTINCT FROM attempt_effective_visibility
       OR NEW.output_safety_reason IS DISTINCT FROM attempt_reason
       OR NEW.output_safety_schema IS DISTINCT FROM attempt_schema THEN
        RAISE EXCEPTION 'attempt log safety must equal the immutable attempt snapshot'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'attempt_log_streams_attempt_safety_snapshot';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER attempt_log_streams_validate_output_safety
BEFORE INSERT ON attempt_log_streams
FOR EACH ROW
EXECUTE FUNCTION automata_validate_attempt_log_safety_snapshot();

-- Artifact admission inherits both the attempt exposure ceiling and the run's
-- immutable requested artifact audience. Dashboard visibility remains
-- independent and deliberately does not participate in this check.
CREATE FUNCTION automata_validate_artifact_safety_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    attempt_exposure TEXT;
    run_artifact_visibility TEXT;
BEGIN
    SELECT secret_exposure_class
    INTO attempt_exposure
    FROM job_attempts
    WHERE id = NEW.attempt_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    SELECT requested_artifact_visibility
    INTO run_artifact_visibility
    FROM workflow_runs
    WHERE id = NEW.run_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF NEW.secret_exposure_class IS DISTINCT FROM attempt_exposure THEN
        RAISE EXCEPTION 'artifact exposure must equal the immutable attempt ceiling'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_artifacts_attempt_exposure_snapshot';
    END IF;
    IF NEW.requested_visibility IS DISTINCT FROM run_artifact_visibility THEN
        RAISE EXCEPTION 'artifact audience must equal the immutable run request'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_artifacts_run_visibility_snapshot';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_artifacts_validate_output_safety
BEFORE INSERT ON workflow_artifacts
FOR EACH ROW
EXECUTE FUNCTION automata_validate_artifact_safety_snapshot();

CREATE FUNCTION automata_attempt_log_safety_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.secret_exposure_class IS DISTINCT FROM OLD.secret_exposure_class
       OR NEW.raw_log_disposition IS DISTINCT FROM OLD.raw_log_disposition
       OR NEW.requested_visibility IS DISTINCT FROM OLD.requested_visibility
       OR NEW.effective_visibility IS DISTINCT FROM OLD.effective_visibility
       OR NEW.output_safety_reason IS DISTINCT FROM OLD.output_safety_reason
       OR NEW.output_safety_schema IS DISTINCT FROM OLD.output_safety_schema THEN
        RAISE EXCEPTION 'attempt log safety snapshots are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'attempt_log_streams_output_safety_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER attempt_log_streams_output_safety_immutable
BEFORE UPDATE ON attempt_log_streams
FOR EACH ROW
EXECUTE FUNCTION automata_attempt_log_safety_immutable();

CREATE FUNCTION automata_artifact_safety_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.secret_exposure_class IS DISTINCT FROM OLD.secret_exposure_class
       OR NEW.requested_visibility IS DISTINCT FROM OLD.requested_visibility
       OR NEW.effective_visibility IS DISTINCT FROM OLD.effective_visibility
       OR NEW.publication_safety_reason IS DISTINCT FROM OLD.publication_safety_reason
       OR NEW.publication_safety_schema IS DISTINCT FROM OLD.publication_safety_schema THEN
        RAISE EXCEPTION 'artifact safety snapshots are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_artifacts_output_safety_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_artifacts_output_safety_immutable
BEFORE UPDATE ON workflow_artifacts
FOR EACH ROW
EXECUTE FUNCTION automata_artifact_safety_immutable();

-- Only provider identity, display state, and capability flags are plaintext.
-- All adapter configuration (including paths, namespaces, endpoints, and
-- credentials) uses the authenticated encrypted envelope below.
CREATE TABLE secret_providers (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    provider_id TEXT NOT NULL,
    adapter_kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    supports_create_version BOOLEAN NOT NULL,
    supports_destroy_version BOOLEAN NOT NULL,
    supports_dynamic_leases BOOLEAN NOT NULL,
    supports_renew_leases BOOLEAN NOT NULL,
    supports_revoke_leases BOOLEAN NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'unconfigured',
    health TEXT NOT NULL DEFAULT 'unknown',
    revision BIGINT NOT NULL DEFAULT 1,
    created_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_providers_primary_key PRIMARY KEY (tenant_id, provider_id),
    CONSTRAINT secret_providers_id_shape CHECK (
        octet_length(provider_id) BETWEEN 1 AND 64
        AND provider_id ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'
    ),
    CONSTRAINT secret_providers_adapter_kind_shape CHECK (
        octet_length(adapter_kind) BETWEEN 1 AND 128
        AND adapter_kind ~ '^[a-z0-9][a-z0-9._:-]*$'
    ),
    CONSTRAINT secret_providers_display_name_shape CHECK (
        octet_length(display_name) BETWEEN 1 AND 255
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT secret_providers_capability_dependencies CHECK (
        (NOT supports_renew_leases OR supports_dynamic_leases)
        AND (NOT supports_revoke_leases OR supports_dynamic_leases)
    ),
    CONSTRAINT secret_providers_status CHECK (
        status IN ('unconfigured', 'active', 'disabled')
    ),
    CONSTRAINT secret_providers_health CHECK (
        health IN ('unknown', 'healthy', 'degraded', 'unavailable')
    ),
    CONSTRAINT secret_providers_revision_positive CHECK (revision > 0),
    CONSTRAINT secret_providers_time_monotonic CHECK (updated_at_ms >= created_at_ms),
    CONSTRAINT secret_providers_creator_membership
        FOREIGN KEY (tenant_id, created_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX secret_providers_one_default
    ON secret_providers (tenant_id)
    WHERE is_default;

CREATE TABLE secret_provider_configuration_envelopes (
    tenant_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    envelope_generation BIGINT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    wrapped_data_key BYTEA NOT NULL,
    wrapping_key_id TEXT NOT NULL,
    envelope_schema INTEGER NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_provider_configuration_envelopes_primary_key PRIMARY KEY (
        tenant_id, provider_id, envelope_generation
    ),
    CONSTRAINT secret_provider_configuration_envelopes_provider
        FOREIGN KEY (tenant_id, provider_id)
        REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT,
    CONSTRAINT secret_provider_configuration_envelopes_generation_positive CHECK (
        envelope_generation > 0
    ),
    CONSTRAINT secret_provider_configuration_envelopes_ciphertext_shape CHECK (
        octet_length(ciphertext) BETWEEN 1 AND 131072
    ),
    CONSTRAINT secret_provider_configuration_envelopes_nonce_shape CHECK (
        octet_length(nonce) = 12
    ),
    CONSTRAINT secret_provider_configuration_envelopes_wrapped_key_shape CHECK (
        octet_length(wrapped_data_key) BETWEEN 1 AND 4096
    ),
    CONSTRAINT secret_provider_configuration_envelopes_key_id_shape CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 128
        AND wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT secret_provider_configuration_envelopes_schema CHECK (
        envelope_schema = 1
    )
);

CREATE TABLE secret_provider_configuration_envelope_heads (
    tenant_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    envelope_generation BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_provider_configuration_envelope_heads_primary_key PRIMARY KEY (
        tenant_id, provider_id
    ),
    CONSTRAINT secret_provider_configuration_envelope_heads_envelope
        FOREIGN KEY (tenant_id, provider_id, envelope_generation)
        REFERENCES secret_provider_configuration_envelopes(
            tenant_id, provider_id, envelope_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_provider_configuration_envelope_heads_revision_positive CHECK (
        revision > 0
    )
);

CREATE FUNCTION automata_secret_provider_configuration_envelopes_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'secret provider configuration envelopes are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_provider_configuration_envelopes_immutable';
END;
$automata$;

CREATE TRIGGER secret_provider_configuration_envelopes_immutable
BEFORE UPDATE ON secret_provider_configuration_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_provider_configuration_envelopes_immutable();

CREATE FUNCTION automata_secret_provider_configuration_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM secret_provider_configuration_envelope_heads
        WHERE tenant_id = OLD.tenant_id
          AND provider_id = OLD.provider_id
          AND envelope_generation = OLD.envelope_generation
    ) THEN
        RAISE EXCEPTION 'current provider configuration envelope cannot be removed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_provider_configuration_envelopes_current';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE TRIGGER secret_provider_configuration_envelopes_delete_guard
BEFORE DELETE ON secret_provider_configuration_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_provider_configuration_delete_guard();

INSERT INTO secret_providers (
    tenant_id, provider_id, adapter_kind, display_name,
    supports_create_version, supports_destroy_version,
    supports_dynamic_leases, supports_renew_leases, supports_revoke_leases,
    is_default, status, health, revision, created_at_ms, updated_at_ms
)
SELECT
    id, 'builtin', 'builtin_postgres', 'Built-in encrypted PostgreSQL',
    TRUE, TRUE, FALSE, FALSE, FALSE,
    TRUE, 'unconfigured', 'unknown', 1, created_at_ms, updated_at_ms
FROM tenants;

CREATE FUNCTION automata_seed_builtin_secret_provider()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    INSERT INTO secret_providers (
        tenant_id, provider_id, adapter_kind, display_name,
        supports_create_version, supports_destroy_version,
        supports_dynamic_leases, supports_renew_leases, supports_revoke_leases,
        is_default, status, health, revision, created_at_ms, updated_at_ms
    ) VALUES (
        NEW.id, 'builtin', 'builtin_postgres', 'Built-in encrypted PostgreSQL',
        TRUE, TRUE, FALSE, FALSE, FALSE,
        TRUE, 'unconfigured', 'unknown', 1, NEW.created_at_ms, NEW.updated_at_ms
    );
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER tenants_seed_builtin_secret_provider
AFTER INSERT ON tenants
FOR EACH ROW
EXECUTE FUNCTION automata_seed_builtin_secret_provider();

CREATE TABLE repository_environments (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    id UUID NOT NULL,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    protection_mode TEXT NOT NULL DEFAULT 'unprotected',
    required_approvals SMALLINT NOT NULL DEFAULT 0,
    prevent_self_review BOOLEAN NOT NULL DEFAULT TRUE,
    status TEXT NOT NULL DEFAULT 'active',
    revision BIGINT NOT NULL DEFAULT 1,
    created_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT repository_environments_primary_key PRIMARY KEY (
        tenant_id, repository_id, id
    ),
    CONSTRAINT repository_environments_tenant_id_unique UNIQUE (tenant_id, id),
    CONSTRAINT repository_environments_name_unique UNIQUE (
        tenant_id, repository_id, normalized_name
    ),
    CONSTRAINT repository_environments_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT repository_environments_name_shape CHECK (
        octet_length(name) BETWEEN 1 AND 255
        AND name !~ '[[:cntrl:]]'
        AND octet_length(normalized_name) BETWEEN 1 AND 255
        AND normalized_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT repository_environments_protection_mode CHECK (
        protection_mode IN ('unprotected', 'required_approvals')
    ),
    CONSTRAINT repository_environments_protection_shape CHECK (
        (protection_mode = 'unprotected' AND required_approvals = 0)
        OR (
            protection_mode = 'required_approvals'
            AND required_approvals BETWEEN 1 AND 25
        )
    ),
    CONSTRAINT repository_environments_status CHECK (
        status IN ('active', 'disabled')
    ),
    CONSTRAINT repository_environments_revision_positive CHECK (revision > 0),
    CONSTRAINT repository_environments_time_monotonic CHECK (
        updated_at_ms >= created_at_ms
    ),
    CONSTRAINT repository_environments_creator_membership
        FOREIGN KEY (tenant_id, created_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE TABLE protected_environment_approval_requests (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    environment_id UUID NOT NULL,
    run_id UUID NOT NULL,
    job_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    id UUID NOT NULL,
    required_approvals SMALLINT NOT NULL,
    prevent_self_review BOOLEAN NOT NULL,
    requested_by_principal_id UUID,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    resolved_at_ms BIGINT,
    resolution_reason TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT protected_environment_approval_requests_primary_key PRIMARY KEY (
        tenant_id, id
    ),
    CONSTRAINT protected_environment_approval_requests_workload_unique UNIQUE (
        tenant_id, repository_id, environment_id, run_id, job_id, attempt_id, id
    ),
    CONSTRAINT protected_environment_approval_requests_environment
        FOREIGN KEY (tenant_id, repository_id, environment_id)
        REFERENCES repository_environments(tenant_id, repository_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT protected_environment_approval_requests_repository_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE CASCADE,
    CONSTRAINT protected_environment_approval_requests_run_job
        FOREIGN KEY (run_id, job_id)
        REFERENCES jobs(run_id, id) ON DELETE CASCADE,
    CONSTRAINT protected_environment_approval_requests_job_attempt
        FOREIGN KEY (job_id, attempt_id)
        REFERENCES job_attempts(job_id, id) ON DELETE CASCADE,
    CONSTRAINT protected_environment_approval_requests_requester_membership
        FOREIGN KEY (tenant_id, requested_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT protected_environment_approval_requests_required_count CHECK (
        required_approvals BETWEEN 1 AND 25
    ),
    CONSTRAINT protected_environment_approval_requests_status CHECK (
        status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')
    ),
    CONSTRAINT protected_environment_approval_requests_lifetime CHECK (
        expires_at_ms > created_at_ms
    ),
    -- Resolution values are closed codes, never arbitrary reviewer/provider
    -- text that could accidentally persist a credential.
    CONSTRAINT protected_environment_approval_requests_status_shape CHECK ((
        (
            status = 'pending'
            AND resolved_at_ms IS NULL
            AND resolution_reason IS NULL
        ) OR (
            status = 'approved'
            AND resolved_at_ms >= created_at_ms
            AND resolution_reason IN (
                'approval_threshold_met', 'administrative_approval'
            )
        ) OR (
            status = 'rejected'
            AND resolved_at_ms >= created_at_ms
            AND resolution_reason IN (
                'approval_rejected', 'administrative_rejection'
            )
        ) OR (
            status = 'expired'
            AND resolved_at_ms >= created_at_ms
            AND resolution_reason = 'approval_expired'
        ) OR (
            status = 'cancelled'
            AND resolved_at_ms >= created_at_ms
            AND resolution_reason IN (
                'workload_cancelled', 'environment_disabled', 'policy_changed'
            )
        )
    ) IS TRUE),
    CONSTRAINT protected_environment_approval_requests_revision_positive CHECK (
        revision > 0
    )
);

CREATE INDEX protected_environment_approval_requests_pending
    ON protected_environment_approval_requests (
        tenant_id, repository_id, environment_id, created_at_ms, id
    ) WHERE status = 'pending';

CREATE TABLE protected_environment_approval_decisions (
    tenant_id TEXT NOT NULL,
    request_id UUID NOT NULL,
    principal_id UUID NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    decided_at_ms BIGINT NOT NULL,
    CONSTRAINT protected_environment_approval_decisions_primary_key PRIMARY KEY (
        tenant_id, request_id, principal_id
    ),
    CONSTRAINT protected_environment_approval_decisions_request
        FOREIGN KEY (tenant_id, request_id)
        REFERENCES protected_environment_approval_requests(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT protected_environment_approval_decisions_principal_membership
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT protected_environment_approval_decisions_decision CHECK (
        decision IN ('approve', 'reject')
    ),
    CONSTRAINT protected_environment_approval_decisions_reason_code CHECK (
        reason IS NULL OR reason IN (
            'policy_reviewed', 'change_reviewed', 'security_reviewed',
            'administrative_review'
        )
    )
);

CREATE TABLE secrets (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id UUID NOT NULL,
    canonical_name TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    repository_id UUID,
    environment_id UUID,
    provider_id TEXT NOT NULL,
    current_version_id UUID,
    current_version_number BIGINT,
    status TEXT NOT NULL DEFAULT 'provisioning',
    revision BIGINT NOT NULL DEFAULT 1,
    created_by_principal_id UUID,
    updated_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    deleted_at_ms BIGINT,
    CONSTRAINT secrets_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT secrets_provider_unique UNIQUE (tenant_id, id, provider_id),
    CONSTRAINT secrets_scope_kind_unique UNIQUE (tenant_id, id, scope_kind),
    CONSTRAINT secrets_scope_unique UNIQUE (
        tenant_id, id, scope_kind, repository_id, environment_id
    ),
    CONSTRAINT secrets_provider
        FOREIGN KEY (tenant_id, provider_id)
        REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT,
    CONSTRAINT secrets_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT secrets_environment
        FOREIGN KEY (tenant_id, repository_id, environment_id)
        REFERENCES repository_environments(tenant_id, repository_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT secrets_name_shape CHECK (
        octet_length(canonical_name) BETWEEN 1 AND 255
        AND canonical_name ~ '^[A-Z_][A-Z0-9_]*$'
        AND canonical_name !~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'
    ),
    CONSTRAINT secrets_scope_kind CHECK (
        scope_kind IN ('tenant', 'repository', 'environment')
    ),
    CONSTRAINT secrets_scope_shape CHECK ((
        (
            scope_kind = 'tenant'
            AND repository_id IS NULL
            AND environment_id IS NULL
        ) OR (
            scope_kind = 'repository'
            AND repository_id IS NOT NULL
            AND environment_id IS NULL
        ) OR (
            scope_kind = 'environment'
            AND repository_id IS NOT NULL
            AND environment_id IS NOT NULL
        )
    ) IS TRUE),
    CONSTRAINT secrets_status CHECK (
        status IN ('provisioning', 'active', 'disabled', 'deleted')
    ),
    CONSTRAINT secrets_status_shape CHECK ((
        (
            status = 'provisioning'
            AND current_version_id IS NULL
            AND current_version_number IS NULL
            AND deleted_at_ms IS NULL
        ) OR (
            status IN ('active', 'disabled')
            AND current_version_id IS NOT NULL
            AND current_version_number > 0
            AND deleted_at_ms IS NULL
        ) OR (
            status = 'deleted'
            AND current_version_id IS NOT NULL
            AND current_version_number > 0
            AND deleted_at_ms >= created_at_ms
        )
    ) IS TRUE),
    CONSTRAINT secrets_revision_positive CHECK (revision > 0),
    CONSTRAINT secrets_time_monotonic CHECK (updated_at_ms >= created_at_ms),
    CONSTRAINT secrets_creator_membership
        FOREIGN KEY (tenant_id, created_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT secrets_updater_membership
        FOREIGN KEY (tenant_id, updated_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX secrets_live_tenant_name
    ON secrets (tenant_id, canonical_name)
    WHERE status <> 'deleted' AND scope_kind = 'tenant';

CREATE UNIQUE INDEX secrets_live_repository_name
    ON secrets (tenant_id, repository_id, canonical_name)
    WHERE status <> 'deleted' AND scope_kind = 'repository';

CREATE UNIQUE INDEX secrets_live_environment_name
    ON secrets (tenant_id, repository_id, environment_id, canonical_name)
    WHERE status <> 'deleted' AND scope_kind = 'environment';

-- A create_request_id winner is safe to replay only while the referenced
-- logical descriptor remains the same. Lifecycle/current-version fields use
-- explicit revisions, but identity, canonical name, scope, and provider never
-- mutate in place.
CREATE FUNCTION automata_secret_descriptor_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.canonical_name IS DISTINCT FROM OLD.canonical_name
       OR NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.created_by_principal_id IS DISTINCT FROM OLD.created_by_principal_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'logical secret descriptors are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secrets_descriptor_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secrets_descriptor_immutable
BEFORE UPDATE ON secrets
FOR EACH ROW
EXECUTE FUNCTION automata_secret_descriptor_immutable();

CREATE TABLE secret_policies (
    tenant_id TEXT NOT NULL,
    secret_id UUID NOT NULL,
    secret_scope_kind TEXT NOT NULL,
    tenant_repository_access_mode TEXT NOT NULL DEFAULT 'selected_repositories',
    minimum_event_trust TEXT NOT NULL DEFAULT 'trusted',
    allow_fork_pull_requests BOOLEAN NOT NULL DEFAULT FALSE,
    allow_dependabot BOOLEAN NOT NULL DEFAULT FALSE,
    reusable_workflow_mode TEXT NOT NULL DEFAULT 'disabled',
    revision BIGINT NOT NULL DEFAULT 1,
    updated_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_policies_primary_key PRIMARY KEY (tenant_id, secret_id),
    CONSTRAINT secret_policies_secret_scope
        FOREIGN KEY (
            tenant_id, secret_id, secret_scope_kind
        ) REFERENCES secrets(tenant_id, id, scope_kind) ON DELETE CASCADE,
    CONSTRAINT secret_policies_repository_access_mode CHECK (
        tenant_repository_access_mode IN (
            'selected_repositories', 'all_repositories', 'scope_only'
        )
    ),
    CONSTRAINT secret_policies_scope_access_shape CHECK (
        (
            secret_scope_kind = 'tenant'
            AND tenant_repository_access_mode IN (
                'selected_repositories', 'all_repositories'
            )
        ) OR (
            secret_scope_kind IN ('repository', 'environment')
            AND tenant_repository_access_mode = 'scope_only'
        )
    ),
    CONSTRAINT secret_policies_event_trust CHECK (
        minimum_event_trust IN ('trusted', 'untrusted')
    ),
    CONSTRAINT secret_policies_reusable_workflow_mode CHECK (
        reusable_workflow_mode IN ('disabled', 'explicit_only')
    ),
    CONSTRAINT secret_policies_revision_positive CHECK (revision > 0),
    CONSTRAINT secret_policies_time_monotonic CHECK (updated_at_ms >= created_at_ms),
    CONSTRAINT secret_policies_updater_membership
        FOREIGN KEY (tenant_id, updated_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE TABLE secret_repository_access (
    tenant_id TEXT NOT NULL,
    secret_id UUID NOT NULL,
    secret_scope_kind TEXT NOT NULL DEFAULT 'tenant',
    repository_id UUID NOT NULL,
    granted_by_principal_id UUID,
    granted_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_repository_access_primary_key PRIMARY KEY (
        tenant_id, secret_id, repository_id
    ),
    CONSTRAINT secret_repository_access_tenant_scope CHECK (
        secret_scope_kind = 'tenant'
    ),
    CONSTRAINT secret_repository_access_secret_scope
        FOREIGN KEY (tenant_id, secret_id, secret_scope_kind)
        REFERENCES secrets(tenant_id, id, scope_kind) ON DELETE CASCADE,
    CONSTRAINT secret_repository_access_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT secret_repository_access_grantor_membership
        FOREIGN KEY (tenant_id, granted_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE TABLE secret_versions (
    tenant_id TEXT NOT NULL,
    id UUID NOT NULL,
    secret_id UUID NOT NULL,
    version_number BIGINT NOT NULL,
    provider_id TEXT NOT NULL,
    create_request_id TEXT NOT NULL,
    storage_kind TEXT NOT NULL,
    created_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_versions_primary_key PRIMARY KEY (
        tenant_id, id
    ),
    CONSTRAINT secret_versions_secret_number_unique UNIQUE (
        tenant_id, secret_id, version_number
    ),
    CONSTRAINT secret_versions_identity_unique UNIQUE (
        tenant_id, id, secret_id, version_number
    ),
    CONSTRAINT secret_versions_provider_unique UNIQUE (
        tenant_id, id, secret_id, version_number, provider_id
    ),
    CONSTRAINT secret_versions_storage_unique UNIQUE (
        tenant_id, id, secret_id, version_number, storage_kind
    ),
    CONSTRAINT secret_versions_create_request_unique UNIQUE (
        tenant_id, provider_id, create_request_id
    ),
    CONSTRAINT secret_versions_secret_provider
        FOREIGN KEY (tenant_id, secret_id, provider_id)
        REFERENCES secrets(tenant_id, id, provider_id) ON DELETE RESTRICT,
    CONSTRAINT secret_versions_version_positive CHECK (version_number > 0),
    CONSTRAINT secret_versions_create_request_shape CHECK (
        octet_length(create_request_id) BETWEEN 1 AND 255
        AND create_request_id !~ '[[:cntrl:]]'
    ),
    CONSTRAINT secret_versions_storage_kind CHECK (
        storage_kind IN ('built_in_ciphertext', 'external_provider')
    ),
    CONSTRAINT secret_versions_creator_membership
        FOREIGN KEY (tenant_id, created_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

ALTER TABLE secrets
    ADD CONSTRAINT secrets_current_version
        FOREIGN KEY (
            tenant_id, current_version_id, id, current_version_number
        ) REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number
        )
        ON DELETE RESTRICT;

-- External provider locators and version handles are sensitive capabilities,
-- not searchable metadata. Only authenticated encryption envelopes are stored;
-- adapters bind AAD to the immutable tenant/provider/secret/version identity,
-- envelope purpose, generation, and schema before decrypting a reference.
CREATE TABLE secret_provider_locator_envelopes (
    tenant_id TEXT NOT NULL,
    secret_id UUID NOT NULL,
    provider_id TEXT NOT NULL,
    envelope_generation BIGINT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    wrapped_data_key BYTEA NOT NULL,
    wrapping_key_id TEXT NOT NULL,
    envelope_schema INTEGER NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_provider_locator_envelopes_primary_key PRIMARY KEY (
        tenant_id, secret_id, envelope_generation
    ),
    CONSTRAINT secret_provider_locator_envelopes_secret
        FOREIGN KEY (tenant_id, secret_id, provider_id)
        REFERENCES secrets(tenant_id, id, provider_id) ON DELETE RESTRICT,
    CONSTRAINT secret_provider_locator_envelopes_generation_positive CHECK (
        envelope_generation > 0
    ),
    CONSTRAINT secret_provider_locator_envelopes_ciphertext_shape CHECK (
        octet_length(ciphertext) BETWEEN 1 AND 131072
    ),
    CONSTRAINT secret_provider_locator_envelopes_nonce_shape CHECK (
        octet_length(nonce) = 12
    ),
    CONSTRAINT secret_provider_locator_envelopes_wrapped_key_shape CHECK (
        octet_length(wrapped_data_key) BETWEEN 1 AND 4096
    ),
    CONSTRAINT secret_provider_locator_envelopes_key_id_shape CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 128
        AND wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT secret_provider_locator_envelopes_schema CHECK (
        envelope_schema = 1
    )
);

CREATE TABLE secret_provider_locator_envelope_heads (
    tenant_id TEXT NOT NULL,
    secret_id UUID NOT NULL,
    envelope_generation BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_provider_locator_envelope_heads_primary_key PRIMARY KEY (
        tenant_id, secret_id
    ),
    CONSTRAINT secret_provider_locator_envelope_heads_envelope
        FOREIGN KEY (tenant_id, secret_id, envelope_generation)
        REFERENCES secret_provider_locator_envelopes(
            tenant_id, secret_id, envelope_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_provider_locator_envelope_heads_revision_positive CHECK (
        revision > 0
    )
);

CREATE TABLE secret_provider_version_envelopes (
    tenant_id TEXT NOT NULL,
    secret_version_id UUID NOT NULL,
    secret_id UUID NOT NULL,
    version_number BIGINT NOT NULL,
    provider_id TEXT NOT NULL,
    envelope_generation BIGINT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    wrapped_data_key BYTEA NOT NULL,
    wrapping_key_id TEXT NOT NULL,
    envelope_schema INTEGER NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_provider_version_envelopes_primary_key PRIMARY KEY (
        tenant_id, secret_version_id, envelope_generation
    ),
    CONSTRAINT secret_provider_version_envelopes_version
        FOREIGN KEY (
            tenant_id, secret_version_id, secret_id,
            version_number, provider_id
        )
        REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number, provider_id
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_provider_version_envelopes_generation_positive CHECK (
        envelope_generation > 0
    ),
    CONSTRAINT secret_provider_version_envelopes_ciphertext_shape CHECK (
        octet_length(ciphertext) BETWEEN 1 AND 131072
    ),
    CONSTRAINT secret_provider_version_envelopes_nonce_shape CHECK (
        octet_length(nonce) = 12
    ),
    CONSTRAINT secret_provider_version_envelopes_wrapped_key_shape CHECK (
        octet_length(wrapped_data_key) BETWEEN 1 AND 4096
    ),
    CONSTRAINT secret_provider_version_envelopes_key_id_shape CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 128
        AND wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT secret_provider_version_envelopes_schema CHECK (
        envelope_schema = 1
    )
);

CREATE TABLE secret_provider_version_envelope_heads (
    tenant_id TEXT NOT NULL,
    secret_version_id UUID NOT NULL,
    envelope_generation BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_provider_version_envelope_heads_primary_key PRIMARY KEY (
        tenant_id, secret_version_id
    ),
    CONSTRAINT secret_provider_version_envelope_heads_envelope
        FOREIGN KEY (
            tenant_id, secret_version_id, envelope_generation
        ) REFERENCES secret_provider_version_envelopes(
            tenant_id, secret_version_id, envelope_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_provider_version_envelope_heads_revision_positive CHECK (
        revision > 0
    )
);

CREATE FUNCTION automata_secret_provider_reference_envelopes_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'secret provider reference envelopes are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_provider_reference_envelopes_immutable';
END;
$automata$;

CREATE TRIGGER secret_provider_locator_envelopes_immutable
BEFORE UPDATE ON secret_provider_locator_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_provider_reference_envelopes_immutable();

CREATE FUNCTION automata_secret_provider_locator_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_status TEXT;
BEGIN
    SELECT status
    INTO STRICT secret_status
    FROM secrets
    WHERE tenant_id = OLD.tenant_id
      AND id = OLD.secret_id;

    IF secret_status <> 'deleted' THEN
        RAISE EXCEPTION 'provider locators may only be removed for deleted secrets'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_provider_locator_envelopes_deleted_secret';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE TRIGGER secret_provider_locator_envelopes_delete_guard
BEFORE DELETE ON secret_provider_locator_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_provider_locator_delete_guard();

CREATE TRIGGER secret_provider_version_envelopes_immutable
BEFORE UPDATE ON secret_provider_version_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_provider_reference_envelopes_immutable();

CREATE TABLE secret_version_lifecycle (
    tenant_id TEXT NOT NULL,
    secret_version_id UUID NOT NULL,
    secret_id UUID NOT NULL,
    version_number BIGINT NOT NULL,
    provider_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    destroy_request_id TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    changed_by_principal_id UUID,
    changed_at_ms BIGINT NOT NULL,
    destroyed_at_ms BIGINT,
    CONSTRAINT secret_version_lifecycle_primary_key PRIMARY KEY (
        tenant_id, secret_version_id
    ),
    CONSTRAINT secret_version_lifecycle_version
        FOREIGN KEY (
            tenant_id, secret_version_id, secret_id,
            version_number, provider_id
        ) REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number, provider_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT secret_version_lifecycle_status CHECK (
        status IN ('active', 'superseded', 'disabled', 'destroy_pending', 'destroyed')
    ),
    CONSTRAINT secret_version_lifecycle_destroy_shape CHECK ((
        (
            status IN ('active', 'superseded', 'disabled')
            AND destroy_request_id IS NULL
            AND destroyed_at_ms IS NULL
        ) OR (
            status = 'destroy_pending'
            AND octet_length(destroy_request_id) BETWEEN 1 AND 255
            AND destroy_request_id !~ '[[:cntrl:]]'
            AND destroyed_at_ms IS NULL
        ) OR (
            status = 'destroyed'
            AND octet_length(destroy_request_id) BETWEEN 1 AND 255
            AND destroy_request_id !~ '[[:cntrl:]]'
            AND destroyed_at_ms >= changed_at_ms
        )
    ) IS TRUE),
    CONSTRAINT secret_version_lifecycle_revision_positive CHECK (revision > 0),
    CONSTRAINT secret_version_lifecycle_changer_membership
        FOREIGN KEY (tenant_id, changed_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX secret_version_lifecycle_destroy_request_unique
    ON secret_version_lifecycle (tenant_id, provider_id, destroy_request_id)
    WHERE destroy_request_id IS NOT NULL;

CREATE TABLE secret_version_envelopes (
    tenant_id TEXT NOT NULL,
    secret_version_id UUID NOT NULL,
    secret_id UUID NOT NULL,
    version_number BIGINT NOT NULL,
    storage_kind TEXT NOT NULL DEFAULT 'built_in_ciphertext',
    envelope_generation BIGINT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    wrapped_data_key BYTEA NOT NULL,
    wrapping_key_id TEXT NOT NULL,
    envelope_schema INTEGER NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_version_envelopes_primary_key PRIMARY KEY (
        tenant_id, secret_version_id, envelope_generation
    ),
    CONSTRAINT secret_version_envelopes_builtin_version
        FOREIGN KEY (
            tenant_id, secret_version_id, secret_id,
            version_number, storage_kind
        )
        REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number, storage_kind
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_version_envelopes_storage_kind CHECK (
        storage_kind = 'built_in_ciphertext'
    ),
    CONSTRAINT secret_version_envelopes_generation_positive CHECK (
        envelope_generation > 0
    ),
    CONSTRAINT secret_version_envelopes_ciphertext_shape CHECK (
        octet_length(ciphertext) BETWEEN 1 AND 131072
    ),
    CONSTRAINT secret_version_envelopes_nonce_shape CHECK (octet_length(nonce) = 12),
    CONSTRAINT secret_version_envelopes_wrapped_key_shape CHECK (
        octet_length(wrapped_data_key) BETWEEN 1 AND 4096
    ),
    CONSTRAINT secret_version_envelopes_key_id_shape CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 128
        AND wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT secret_version_envelopes_schema CHECK (envelope_schema = 1)
);

CREATE TABLE secret_version_envelope_heads (
    tenant_id TEXT NOT NULL,
    secret_version_id UUID NOT NULL,
    envelope_generation BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_version_envelope_heads_primary_key PRIMARY KEY (
        tenant_id, secret_version_id
    ),
    CONSTRAINT secret_version_envelope_heads_envelope
        FOREIGN KEY (
            tenant_id, secret_version_id, envelope_generation
        ) REFERENCES secret_version_envelopes(
            tenant_id, secret_version_id, envelope_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_version_envelope_heads_revision_positive CHECK (revision > 0)
);

CREATE FUNCTION automata_secret_versions_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'secret versions are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_versions_immutable';
END;
$automata$;

CREATE TRIGGER secret_versions_immutable
BEFORE UPDATE OR DELETE ON secret_versions
FOR EACH ROW
EXECUTE FUNCTION automata_secret_versions_immutable();

CREATE FUNCTION automata_secret_version_envelopes_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'secret version envelopes are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_version_envelopes_immutable';
END;
$automata$;

CREATE TRIGGER secret_version_envelopes_immutable
BEFORE UPDATE ON secret_version_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_envelopes_immutable();

CREATE FUNCTION automata_secret_version_envelope_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    lifecycle_status TEXT;
BEGIN
    SELECT status
    INTO STRICT lifecycle_status
    FROM secret_version_lifecycle
    WHERE tenant_id = OLD.tenant_id
      AND secret_version_id = OLD.secret_version_id;

    IF lifecycle_status <> 'destroy_pending' THEN
        RAISE EXCEPTION 'secret version envelopes may only be cryptographically destroyed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_envelopes_destroy_pending';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE TRIGGER secret_provider_version_envelopes_delete_guard
BEFORE DELETE ON secret_provider_version_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_envelope_delete_guard();

CREATE TRIGGER secret_version_envelopes_delete_guard
BEFORE DELETE ON secret_version_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_envelope_delete_guard();

CREATE FUNCTION automata_secret_version_lifecycle_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.secret_version_id IS DISTINCT FROM OLD.secret_version_id
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.version_number IS DISTINCT FROM OLD.version_number
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id THEN
        RAISE EXCEPTION 'secret version lifecycle identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_identity_immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1
       OR NEW.changed_at_ms < OLD.changed_at_ms THEN
        RAISE EXCEPTION 'secret version lifecycle updates require monotonic CAS'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_cas';
    END IF;
    IF OLD.destroy_request_id IS NOT NULL
       AND NEW.destroy_request_id IS DISTINCT FROM OLD.destroy_request_id THEN
        RAISE EXCEPTION 'secret version destroy request identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_destroy_request_immutable';
    END IF;
    IF NOT (
        (OLD.status = 'active' AND NEW.status IN ('superseded', 'disabled', 'destroy_pending'))
        OR (OLD.status = 'superseded' AND NEW.status IN ('disabled', 'destroy_pending'))
        OR (OLD.status = 'disabled' AND NEW.status IN ('active', 'destroy_pending'))
        OR (OLD.status = 'destroy_pending' AND NEW.status = 'destroyed')
    ) THEN
        RAISE EXCEPTION 'invalid secret version lifecycle transition'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_transition';
    END IF;

    IF NEW.status = 'destroyed'
       AND (
           EXISTS (
               SELECT 1 FROM secret_version_envelopes
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
           OR EXISTS (
               SELECT 1 FROM secret_version_envelope_heads
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
           OR EXISTS (
               SELECT 1 FROM secret_provider_version_envelopes
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
           OR EXISTS (
               SELECT 1 FROM secret_provider_version_envelope_heads
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
       ) THEN
        RAISE EXCEPTION 'cryptographic material must be removed before destroy completes'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_crypto_destroyed';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_version_lifecycle_transition
BEFORE UPDATE ON secret_version_lifecycle
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_lifecycle_transition();

CREATE FUNCTION automata_seed_secret_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    INSERT INTO secret_policies (
        tenant_id, secret_id, secret_scope_kind,
        tenant_repository_access_mode, minimum_event_trust,
        allow_fork_pull_requests, allow_dependabot, reusable_workflow_mode,
        revision, created_at_ms, updated_at_ms
    ) VALUES (
        NEW.tenant_id, NEW.id, NEW.scope_kind,
        CASE
            WHEN NEW.scope_kind = 'tenant' THEN 'selected_repositories'
            ELSE 'scope_only'
        END,
        'trusted', FALSE, FALSE, 'disabled',
        1, NEW.created_at_ms, NEW.updated_at_ms
    );
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secrets_seed_policy
AFTER INSERT ON secrets
FOR EACH ROW
EXECUTE FUNCTION automata_seed_secret_policy();

-- One grant pins an exact immutable secret version to one exact job attempt and
-- fence. The authority digest authenticates the runner-held credential; it is
-- not derived from, and cannot be used to compare, secret values.
CREATE TABLE secret_workload_grants (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    run_id UUID NOT NULL,
    job_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    secret_id UUID NOT NULL,
    secret_version_id UUID NOT NULL,
    secret_version_number BIGINT NOT NULL,
    provider_id TEXT NOT NULL,
    environment_id UUID,
    environment_approval_request_id UUID,
    grant_mode TEXT NOT NULL,
    event_trust TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    authority_digest BYTEA NOT NULL,
    authority_digest_key_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    issued_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT,
    revocation_reason TEXT,
    CONSTRAINT secret_workload_grants_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT secret_workload_grants_attempt_secret_unique UNIQUE (
        tenant_id, attempt_id, secret_id, secret_version_id, grant_mode
    ),
    CONSTRAINT secret_workload_grants_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT secret_workload_grants_repository_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE CASCADE,
    CONSTRAINT secret_workload_grants_run_job
        FOREIGN KEY (run_id, job_id)
        REFERENCES jobs(run_id, id) ON DELETE CASCADE,
    CONSTRAINT secret_workload_grants_job_attempt
        FOREIGN KEY (job_id, attempt_id)
        REFERENCES job_attempts(job_id, id) ON DELETE CASCADE,
    CONSTRAINT secret_workload_grants_secret_version
        FOREIGN KEY (
            tenant_id, secret_version_id, secret_id,
            secret_version_number, provider_id
        ) REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number, provider_id
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_workload_grants_environment
        FOREIGN KEY (tenant_id, repository_id, environment_id)
        REFERENCES repository_environments(tenant_id, repository_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT secret_workload_grants_environment_approval
        FOREIGN KEY (
            tenant_id, repository_id, environment_id, run_id, job_id,
            attempt_id, environment_approval_request_id
        ) REFERENCES protected_environment_approval_requests(
            tenant_id, repository_id, environment_id, run_id, job_id,
            attempt_id, id
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_workload_grants_environment_shape CHECK (
        environment_id IS NOT NULL OR environment_approval_request_id IS NULL
    ),
    CONSTRAINT secret_workload_grants_fencing_token_positive CHECK (fencing_token > 0),
    CONSTRAINT secret_workload_grants_grant_mode CHECK (
        grant_mode IN ('readable_secret', 'capability_only')
    ),
    CONSTRAINT secret_workload_grants_event_trust CHECK (
        event_trust IN ('trusted', 'untrusted')
    ),
    CONSTRAINT secret_workload_grants_source_kind CHECK (
        source_kind IN ('same_repository', 'fork', 'dependabot', 'unknown')
    ),
    CONSTRAINT secret_workload_grants_authority_digest CHECK (
        octet_length(authority_digest) = 32
    ),
    CONSTRAINT secret_workload_grants_authority_key_shape CHECK (
        octet_length(authority_digest_key_id) BETWEEN 1 AND 128
        AND authority_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT secret_workload_grants_authority_unique UNIQUE (
        authority_digest_key_id, authority_digest
    ),
    CONSTRAINT secret_workload_grants_status CHECK (
        status IN ('active', 'revoked', 'expired')
    ),
    CONSTRAINT secret_workload_grants_lifetime CHECK (expires_at_ms > issued_at_ms),
    CONSTRAINT secret_workload_grants_revocation_shape CHECK ((
        (
            status = 'active'
            AND revoked_at_ms IS NULL
            AND revocation_reason IS NULL
        ) OR (
            status = 'revoked'
            AND revoked_at_ms >= issued_at_ms
            AND revocation_reason IN (
                'attempt_completed', 'attempt_cancelled', 'secret_disabled',
                'secret_deleted', 'policy_changed', 'environment_revoked',
                'administrative_revocation', 'integrity_failure'
            )
        ) OR (
            status = 'expired'
            AND revoked_at_ms >= issued_at_ms
            AND revocation_reason = 'grant_expired'
        )
    ) IS TRUE)
);

CREATE INDEX secret_workload_grants_active_attempt
    ON secret_workload_grants (tenant_id, attempt_id, expires_at_ms, id)
    WHERE status = 'active';

CREATE FUNCTION automata_validate_secret_workload_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    stored_scope TEXT;
    stored_repository UUID;
    stored_environment UUID;
    stored_secret_status TEXT;
    stored_version_status TEXT;
    repository_access_mode TEXT;
    minimum_trust TEXT;
    permits_forks BOOLEAN;
    permits_dependabot BOOLEAN;
    attempt_exposure TEXT;
    environment_protection TEXT;
    approval_status TEXT;
BEGIN
    SELECT
        secret.scope_kind,
        secret.repository_id,
        secret.environment_id,
        secret.status,
        policy.tenant_repository_access_mode,
        policy.minimum_event_trust,
        policy.allow_fork_pull_requests,
        policy.allow_dependabot
    INTO STRICT
        stored_scope,
        stored_repository,
        stored_environment,
        stored_secret_status,
        repository_access_mode,
        minimum_trust,
        permits_forks,
        permits_dependabot
    FROM secrets AS secret
    JOIN secret_policies AS policy
      ON policy.tenant_id = secret.tenant_id
     AND policy.secret_id = secret.id
    WHERE secret.tenant_id = NEW.tenant_id
      AND secret.id = NEW.secret_id;

    IF stored_secret_status <> 'active' THEN
        RAISE EXCEPTION 'only active secrets may be granted to workloads'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_active_secret';
    END IF;

    SELECT status
    INTO STRICT stored_version_status
    FROM secret_version_lifecycle
    WHERE tenant_id = NEW.tenant_id
      AND secret_version_id = NEW.secret_version_id;

    IF stored_version_status <> 'active' THEN
        RAISE EXCEPTION 'only active secret versions may be granted to workloads'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_active_version';
    END IF;

    IF stored_scope = 'tenant' THEN
        IF repository_access_mode = 'selected_repositories'
           AND NOT EXISTS (
               SELECT 1
               FROM secret_repository_access AS access
               WHERE access.tenant_id = NEW.tenant_id
                 AND access.secret_id = NEW.secret_id
                 AND access.repository_id = NEW.repository_id
           ) THEN
            RAISE EXCEPTION 'tenant secret is not granted to this repository'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'secret_workload_grants_scope';
        END IF;
    ELSIF stored_scope = 'repository' THEN
        IF stored_repository <> NEW.repository_id THEN
            RAISE EXCEPTION 'repository secret does not enclose this workload'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'secret_workload_grants_scope';
        END IF;
    ELSIF stored_scope = 'environment' THEN
        IF stored_repository <> NEW.repository_id
           OR stored_environment IS DISTINCT FROM NEW.environment_id THEN
            RAISE EXCEPTION 'environment secret does not enclose this workload'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'secret_workload_grants_scope';
        END IF;
    ELSE
        RAISE EXCEPTION 'unknown secret scope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_scope';
    END IF;

    IF minimum_trust = 'trusted' AND NEW.event_trust <> 'trusted' THEN
        RAISE EXCEPTION 'secret policy rejects untrusted events'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_event_policy';
    END IF;
    IF NEW.source_kind = 'fork' AND NOT permits_forks THEN
        RAISE EXCEPTION 'secret policy rejects fork pull requests'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_event_policy';
    END IF;
    IF NEW.source_kind = 'dependabot' AND NOT permits_dependabot THEN
        RAISE EXCEPTION 'secret policy rejects Dependabot workloads'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_event_policy';
    END IF;

    SELECT secret_exposure_class
    INTO STRICT attempt_exposure
    FROM job_attempts
    WHERE id = NEW.attempt_id;

    IF NEW.grant_mode = 'readable_secret'
       AND attempt_exposure <> 'readable_secret' THEN
        RAISE EXCEPTION 'readable grants require a readable-secret attempt cap'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_exposure_class';
    END IF;
    IF NEW.grant_mode = 'capability_only'
       AND attempt_exposure = 'secretless' THEN
        RAISE EXCEPTION 'capability grants require a credential-aware attempt cap'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_exposure_class';
    END IF;

    IF NEW.environment_id IS NOT NULL THEN
        SELECT protection_mode
        INTO STRICT environment_protection
        FROM repository_environments
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND id = NEW.environment_id;

        IF environment_protection = 'required_approvals' THEN
            IF NEW.environment_approval_request_id IS NULL THEN
                RAISE EXCEPTION 'protected environment approval is required'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'secret_workload_grants_environment_approval';
            END IF;
            SELECT status
            INTO STRICT approval_status
            FROM protected_environment_approval_requests
            WHERE tenant_id = NEW.tenant_id
              AND id = NEW.environment_approval_request_id;
            IF approval_status <> 'approved' THEN
                RAISE EXCEPTION 'protected environment is not approved'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'secret_workload_grants_environment_approval';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_workload_grants_validate
BEFORE INSERT ON secret_workload_grants
FOR EACH ROW
EXECUTE FUNCTION automata_validate_secret_workload_grant();

CREATE FUNCTION automata_secret_workload_grant_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.fencing_token IS DISTINCT FROM OLD.fencing_token
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.secret_version_id IS DISTINCT FROM OLD.secret_version_id
       OR NEW.secret_version_number IS DISTINCT FROM OLD.secret_version_number
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.environment_approval_request_id IS DISTINCT FROM OLD.environment_approval_request_id
       OR NEW.grant_mode IS DISTINCT FROM OLD.grant_mode
       OR NEW.event_trust IS DISTINCT FROM OLD.event_trust
       OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
       OR NEW.authority_digest IS DISTINCT FROM OLD.authority_digest
       OR NEW.authority_digest_key_id IS DISTINCT FROM OLD.authority_digest_key_id
       OR NEW.issued_at_ms IS DISTINCT FROM OLD.issued_at_ms
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms THEN
        RAISE EXCEPTION 'workload grant identity and authority are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_workload_grants_identity_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_workload_grants_identity_immutable
BEFORE UPDATE ON secret_workload_grants
FOR EACH ROW
EXECUTE FUNCTION automata_secret_workload_grant_identity_immutable();

CREATE FUNCTION automata_validate_environment_approval_decision()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    request_status TEXT;
    requester UUID;
    self_review_blocked BOOLEAN;
BEGIN
    SELECT status, requested_by_principal_id, prevent_self_review
    INTO STRICT request_status, requester, self_review_blocked
    FROM protected_environment_approval_requests
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.request_id;

    IF request_status <> 'pending' THEN
        RAISE EXCEPTION 'environment approval request is terminal'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_pending';
    END IF;
    IF self_review_blocked AND requester = NEW.principal_id THEN
        RAISE EXCEPTION 'environment requester cannot approve their own workload'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_self_review';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER protected_environment_approval_decisions_validate
BEFORE INSERT ON protected_environment_approval_decisions
FOR EACH ROW
EXECUTE FUNCTION automata_validate_environment_approval_decision();

CREATE TABLE secret_provider_leases (
    tenant_id TEXT NOT NULL,
    id UUID NOT NULL,
    provider_id TEXT NOT NULL,
    workload_grant_id UUID NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    issued_at_seconds BIGINT NOT NULL,
    expires_at_seconds BIGINT NOT NULL,
    renewed_at_seconds BIGINT,
    revoked_at_seconds BIGINT,
    revocation_reason TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT secret_provider_leases_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT secret_provider_leases_provider_unique UNIQUE (
        tenant_id, id, provider_id
    ),
    CONSTRAINT secret_provider_leases_grant_unique UNIQUE (
        tenant_id, provider_id, workload_grant_id
    ),
    CONSTRAINT secret_provider_leases_provider
        FOREIGN KEY (tenant_id, provider_id)
        REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT,
    CONSTRAINT secret_provider_leases_workload_grant
        FOREIGN KEY (tenant_id, workload_grant_id)
        REFERENCES secret_workload_grants(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT secret_provider_leases_status CHECK (
        status IN ('active', 'revocation_pending', 'revoked', 'expired')
    ),
    CONSTRAINT secret_provider_leases_lifetime CHECK (
        issued_at_seconds > 0
        AND expires_at_seconds > issued_at_seconds
        AND (
            renewed_at_seconds IS NULL
            OR renewed_at_seconds >= issued_at_seconds
        )
    ),
    CONSTRAINT secret_provider_leases_revocation_shape CHECK ((
        (
            status = 'active'
            AND revoked_at_seconds IS NULL
            AND revocation_reason IS NULL
        ) OR (
            status = 'revocation_pending'
            AND revoked_at_seconds IS NULL
            AND revocation_reason IN (
                'grant_revoked', 'provider_revocation_requested',
                'secret_destroyed', 'administrative_revocation',
                'integrity_failure'
            )
        ) OR (
            status = 'revoked'
            AND revoked_at_seconds >= issued_at_seconds
            AND revocation_reason IN (
                'grant_revoked', 'provider_revoked', 'secret_destroyed',
                'administrative_revocation', 'integrity_failure'
            )
        ) OR (
            status = 'expired'
            AND revoked_at_seconds >= issued_at_seconds
            AND revocation_reason = 'lease_expired'
        )
    ) IS TRUE),
    CONSTRAINT secret_provider_leases_revision_positive CHECK (revision > 0)
);

CREATE INDEX secret_provider_leases_expiry
    ON secret_provider_leases (expires_at_seconds, tenant_id, id)
    WHERE status IN ('active', 'revocation_pending');

-- Dynamic provider lease handles can authorize renewal or revocation and are
-- therefore encrypted exactly like provider locator/version references.
CREATE TABLE secret_provider_lease_envelopes (
    tenant_id TEXT NOT NULL,
    provider_lease_record_id UUID NOT NULL,
    provider_id TEXT NOT NULL,
    envelope_generation BIGINT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    wrapped_data_key BYTEA NOT NULL,
    wrapping_key_id TEXT NOT NULL,
    envelope_schema INTEGER NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_provider_lease_envelopes_primary_key PRIMARY KEY (
        tenant_id, provider_lease_record_id, envelope_generation
    ),
    CONSTRAINT secret_provider_lease_envelopes_lease
        FOREIGN KEY (tenant_id, provider_lease_record_id, provider_id)
        REFERENCES secret_provider_leases(tenant_id, id, provider_id)
        ON DELETE RESTRICT,
    CONSTRAINT secret_provider_lease_envelopes_generation_positive CHECK (
        envelope_generation > 0
    ),
    CONSTRAINT secret_provider_lease_envelopes_ciphertext_shape CHECK (
        octet_length(ciphertext) BETWEEN 1 AND 131072
    ),
    CONSTRAINT secret_provider_lease_envelopes_nonce_shape CHECK (
        octet_length(nonce) = 12
    ),
    CONSTRAINT secret_provider_lease_envelopes_wrapped_key_shape CHECK (
        octet_length(wrapped_data_key) BETWEEN 1 AND 4096
    ),
    CONSTRAINT secret_provider_lease_envelopes_key_id_shape CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 128
        AND wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT secret_provider_lease_envelopes_schema CHECK (
        envelope_schema = 1
    )
);

CREATE TABLE secret_provider_lease_envelope_heads (
    tenant_id TEXT NOT NULL,
    provider_lease_record_id UUID NOT NULL,
    envelope_generation BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_provider_lease_envelope_heads_primary_key PRIMARY KEY (
        tenant_id, provider_lease_record_id
    ),
    CONSTRAINT secret_provider_lease_envelope_heads_envelope
        FOREIGN KEY (
            tenant_id, provider_lease_record_id, envelope_generation
        ) REFERENCES secret_provider_lease_envelopes(
            tenant_id, provider_lease_record_id, envelope_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_provider_lease_envelope_heads_revision_positive CHECK (
        revision > 0
    )
);

CREATE TRIGGER secret_provider_lease_envelopes_immutable
BEFORE UPDATE ON secret_provider_lease_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_provider_reference_envelopes_immutable();

CREATE FUNCTION automata_secret_provider_lease_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    lease_status TEXT;
BEGIN
    SELECT status
    INTO STRICT lease_status
    FROM secret_provider_leases
    WHERE tenant_id = OLD.tenant_id
      AND id = OLD.provider_lease_record_id;

    IF lease_status NOT IN ('revoked', 'expired') THEN
        RAISE EXCEPTION 'provider lease handles may only be removed when terminal'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_provider_lease_envelopes_terminal_lease';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE TRIGGER secret_provider_lease_envelopes_delete_guard
BEFORE DELETE ON secret_provider_lease_envelopes
FOR EACH ROW
EXECUTE FUNCTION automata_secret_provider_lease_delete_guard();

CREATE TABLE secret_cleanup_outbox (
    sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    operation_id UUID NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    provider_id TEXT NOT NULL,
    cleanup_kind TEXT NOT NULL,
    provider_lease_record_id UUID,
    secret_id UUID,
    secret_version_id UUID,
    version_number BIGINT,
    envelope_generation BIGINT,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at_ms BIGINT NOT NULL,
    locked_by TEXT,
    locked_at_ms BIGINT,
    last_failure_kind TEXT,
    created_at_ms BIGINT NOT NULL,
    completed_at_ms BIGINT,
    CONSTRAINT secret_cleanup_outbox_provider
        FOREIGN KEY (tenant_id, provider_id)
        REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT,
    CONSTRAINT secret_cleanup_outbox_provider_lease
        FOREIGN KEY (tenant_id, provider_lease_record_id)
        REFERENCES secret_provider_leases(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT secret_cleanup_outbox_secret_version
        FOREIGN KEY (
            tenant_id, secret_version_id, secret_id, version_number
        ) REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number
        )
        ON DELETE RESTRICT,
    CONSTRAINT secret_cleanup_outbox_kind CHECK (
        cleanup_kind IN (
            'revoke_provider_lease', 'destroy_secret_version', 'retire_envelope'
        )
    ),
    CONSTRAINT secret_cleanup_outbox_target_shape CHECK ((
        (
            cleanup_kind = 'revoke_provider_lease'
            AND provider_lease_record_id IS NOT NULL
            AND secret_id IS NULL
            AND secret_version_id IS NULL
            AND version_number IS NULL
            AND envelope_generation IS NULL
        ) OR (
            cleanup_kind = 'destroy_secret_version'
            AND provider_lease_record_id IS NULL
            AND secret_id IS NOT NULL
            AND secret_version_id IS NOT NULL
            AND version_number IS NOT NULL
            AND envelope_generation IS NULL
        ) OR (
            cleanup_kind = 'retire_envelope'
            AND provider_lease_record_id IS NULL
            AND secret_id IS NOT NULL
            AND secret_version_id IS NOT NULL
            AND version_number IS NOT NULL
            AND envelope_generation IS NOT NULL
        )
    ) IS TRUE),
    CONSTRAINT secret_cleanup_outbox_status CHECK (
        status IN ('pending', 'in_progress', 'completed', 'dead_letter')
    ),
    CONSTRAINT secret_cleanup_outbox_attempts_bounded CHECK (
        attempts BETWEEN 0 AND 100
    ),
    CONSTRAINT secret_cleanup_outbox_lock_shape CHECK ((
        (
            status = 'in_progress'
            AND octet_length(locked_by) BETWEEN 1 AND 255
            AND locked_by !~ '[[:cntrl:]]'
            AND locked_at_ms IS NOT NULL
            AND completed_at_ms IS NULL
        ) OR (
            status <> 'in_progress'
            AND locked_by IS NULL
            AND locked_at_ms IS NULL
        )
    ) IS TRUE),
    CONSTRAINT secret_cleanup_outbox_completion_shape CHECK ((
        (status = 'completed' AND completed_at_ms >= created_at_ms)
        OR (status <> 'completed' AND completed_at_ms IS NULL)
    ) IS TRUE),
    CONSTRAINT secret_cleanup_outbox_failure_kind CHECK (
        last_failure_kind IS NULL OR last_failure_kind IN (
            'invalid_request', 'unsupported', 'unauthorized', 'forbidden',
            'not_found', 'conflict', 'rate_limited', 'unavailable',
            'integrity_failure', 'invalid_response'
        )
    )
);

CREATE INDEX secret_cleanup_outbox_ready
    ON secret_cleanup_outbox (next_attempt_at_ms, sequence)
    WHERE status = 'pending';

CREATE TABLE secret_key_rotations (
    tenant_id TEXT NOT NULL,
    id UUID NOT NULL,
    provider_id TEXT NOT NULL,
    from_wrapping_key_id TEXT NOT NULL,
    to_wrapping_key_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    discovered_versions BIGINT NOT NULL DEFAULT 0,
    completed_versions BIGINT NOT NULL DEFAULT 0,
    initiated_by_principal_id UUID,
    created_at_ms BIGINT NOT NULL,
    started_at_ms BIGINT,
    completed_at_ms BIGINT,
    failure_kind TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT secret_key_rotations_primary_key PRIMARY KEY (tenant_id, id),
    CONSTRAINT secret_key_rotations_provider
        FOREIGN KEY (tenant_id, provider_id)
        REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT,
    CONSTRAINT secret_key_rotations_key_ids_shape CHECK (
        octet_length(from_wrapping_key_id) BETWEEN 1 AND 128
        AND from_wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        AND octet_length(to_wrapping_key_id) BETWEEN 1 AND 128
        AND to_wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        AND from_wrapping_key_id <> to_wrapping_key_id
    ),
    CONSTRAINT secret_key_rotations_status CHECK (
        status IN ('pending', 'running', 'completed', 'failed')
    ),
    CONSTRAINT secret_key_rotations_progress CHECK (
        discovered_versions >= 0
        AND completed_versions BETWEEN 0 AND discovered_versions
    ),
    CONSTRAINT secret_key_rotations_status_shape CHECK ((
        (
            status = 'pending'
            AND started_at_ms IS NULL
            AND completed_at_ms IS NULL
            AND failure_kind IS NULL
        ) OR (
            status = 'running'
            AND started_at_ms >= created_at_ms
            AND completed_at_ms IS NULL
            AND failure_kind IS NULL
        ) OR (
            status = 'completed'
            AND started_at_ms >= created_at_ms
            AND completed_at_ms >= started_at_ms
            AND completed_versions = discovered_versions
            AND failure_kind IS NULL
        ) OR (
            status = 'failed'
            AND started_at_ms >= created_at_ms
            AND completed_at_ms >= started_at_ms
            AND failure_kind IN (
                'invalid_request', 'unsupported', 'unauthorized', 'forbidden',
                'not_found', 'conflict', 'rate_limited', 'unavailable',
                'integrity_failure', 'invalid_response', 'key_unavailable',
                'encryption_failure', 'decryption_failure', 'storage_failure'
            )
        )
    ) IS TRUE),
    CONSTRAINT secret_key_rotations_revision_positive CHECK (revision > 0),
    CONSTRAINT secret_key_rotations_initiator_membership
        FOREIGN KEY (tenant_id, initiated_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX secret_key_rotations_one_active_provider
    ON secret_key_rotations (tenant_id, provider_id)
    WHERE status IN ('pending', 'running');

CREATE TABLE secret_key_rotation_items (
    tenant_id TEXT NOT NULL,
    rotation_id UUID NOT NULL,
    secret_version_id UUID NOT NULL,
    secret_id UUID NOT NULL,
    version_number BIGINT NOT NULL,
    previous_envelope_generation BIGINT NOT NULL,
    replacement_envelope_generation BIGINT,
    status TEXT NOT NULL DEFAULT 'pending',
    failure_kind TEXT,
    created_at_ms BIGINT NOT NULL,
    completed_at_ms BIGINT,
    CONSTRAINT secret_key_rotation_items_primary_key PRIMARY KEY (
        tenant_id, rotation_id, secret_version_id
    ),
    CONSTRAINT secret_key_rotation_items_rotation
        FOREIGN KEY (tenant_id, rotation_id)
        REFERENCES secret_key_rotations(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT secret_key_rotation_items_version
        FOREIGN KEY (
            tenant_id, secret_version_id, secret_id, version_number
        ) REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_key_rotation_items_status CHECK (
        status IN ('pending', 'completed', 'failed')
    ),
    CONSTRAINT secret_key_rotation_items_status_shape CHECK ((
        (
            status = 'pending'
            AND replacement_envelope_generation IS NULL
            AND failure_kind IS NULL
            AND completed_at_ms IS NULL
        ) OR (
            status = 'completed'
            AND replacement_envelope_generation IS NOT NULL
            AND replacement_envelope_generation <> previous_envelope_generation
            AND failure_kind IS NULL
            AND completed_at_ms >= created_at_ms
        ) OR (
            status = 'failed'
            AND failure_kind IN (
                'invalid_request', 'unsupported', 'unauthorized', 'forbidden',
                'not_found', 'conflict', 'rate_limited', 'unavailable',
                'integrity_failure', 'invalid_response', 'key_unavailable',
                'encryption_failure', 'decryption_failure', 'storage_failure'
            )
            AND completed_at_ms >= created_at_ms
        )
    ) IS TRUE)
);

-- Envelope existence is checked when an item is written, while the item keeps
-- its audit identity after later cryptographic destruction removes the bytes.
CREATE FUNCTION automata_validate_secret_key_rotation_item()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM secret_version_envelopes
        WHERE tenant_id = NEW.tenant_id
          AND secret_version_id = NEW.secret_version_id
          AND envelope_generation = NEW.previous_envelope_generation
    ) THEN
        RAISE EXCEPTION 'rotation source envelope does not exist'
            USING ERRCODE = 'foreign_key_violation',
                  CONSTRAINT = 'secret_key_rotation_items_previous_envelope';
    END IF;
    IF NEW.replacement_envelope_generation IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
           FROM secret_version_envelopes
           WHERE tenant_id = NEW.tenant_id
             AND secret_version_id = NEW.secret_version_id
             AND envelope_generation = NEW.replacement_envelope_generation
       ) THEN
        RAISE EXCEPTION 'rotation replacement envelope does not exist'
            USING ERRCODE = 'foreign_key_violation',
                  CONSTRAINT = 'secret_key_rotation_items_replacement_envelope';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_key_rotation_items_validate_envelopes
BEFORE INSERT OR UPDATE ON secret_key_rotation_items
FOR EACH ROW
EXECUTE FUNCTION automata_validate_secret_key_rotation_item();
