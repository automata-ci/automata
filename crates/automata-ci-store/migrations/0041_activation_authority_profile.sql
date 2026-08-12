-- Current-only exact authority-profile binding for GitHub logical activation.
-- No pre-profile provider or activation state is inferred or backfilled.

LOCK TABLE github_provider_manifest_revisions,
    github_workflow_run_subject_evidence, github_provider_delivery_evidence,
    workflow_plan_v2_jobs, workflow_plan_v2_activation_preparation_claims,
    workflow_plan_v2_activation_preparations,
    workflow_plan_v2_activation_publications,
    workflow_plan_v2_materialization_claims,
    workflow_plan_v2_concrete_jobs,
    github_oidc_authorities, github_oidc_issuance_slots,
    github_runtime_authority_issuances
    IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM github_provider_manifest_revisions)
        OR EXISTS (SELECT 1 FROM github_workflow_run_subject_evidence)
        OR EXISTS (SELECT 1 FROM github_provider_delivery_evidence)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_jobs)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_activation_preparation_claims)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_activation_preparations)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_activation_publications)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_materialization_claims)
        OR EXISTS (SELECT 1 FROM workflow_plan_v2_concrete_jobs)
        OR EXISTS (SELECT 1 FROM github_oidc_authorities)
        OR EXISTS (SELECT 1 FROM github_oidc_issuance_slots)
        OR EXISTS (SELECT 1 FROM github_runtime_authority_issuances)
    THEN
        RAISE EXCEPTION 'pre-profile provider and activation state must be recreated before authority-profile v2'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'activation_authority_profile_current_only';
    END IF;
END;
$automata$;

ALTER TABLE github_provider_manifest_revisions
    DROP CONSTRAINT github_provider_manifest_revisions_digest_canonical,
    ADD COLUMN authority_profile TEXT COLLATE "C" NOT NULL,
    ADD CONSTRAINT github_provider_manifest_revisions_authority_profile CHECK (
        authority_profile IN ('standard', 'credential_free')
    );

CREATE OR REPLACE FUNCTION automata_github_provider_manifest_digest(
    github_provider_manifest_revisions
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.github-provider-manifest.v2', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).tenant_id, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(($1).repository_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(($1).provider_connection_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).provider_installation_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).github_repository_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_repository_name, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).repository_visibility, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).github_app_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_app_client_id, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_app_jwt_issuer_kind, 'UTF8'))
    || automata_github_provider_manifest_digest_part(($1).app_key_spki_sha256)
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).app_configuration_revision))
    || automata_github_provider_manifest_digest_part(($1).webhook_verifier_fingerprint_sha256)
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).webhook_verifier_revision))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).policy_revision))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).authority_profile, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).manifest_revision))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).workflow_path, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).event_name, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).git_ref, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).check_subject_key, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).check_name, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_web_origin, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_api_origin, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_archive_origin, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_rest_api_version, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_rest_accept, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).github_archive_accept, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).repository_source_authentication, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).repository_source_revision, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(($1).repository_archive_format, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).webhook_max_body_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).webhook_accept_timeout_ms))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).push_webhook_max_commits))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).path_filter_max_commits))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).path_filter_max_changed_files))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_compressed_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_decompressed_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_entries))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_expanded_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_entry_path_bytes))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).archive_max_workflows))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).workflow_max_bytes))
)
$automata$;

ALTER TABLE github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_digest_canonical CHECK (
        manifest_digest = automata_github_provider_manifest_digest(
            github_provider_manifest_revisions
        )
    );

CREATE OR REPLACE FUNCTION automata_github_provider_manifest_current_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    prior github_provider_manifest_revisions%ROWTYPE;
    replacement github_provider_manifest_revisions%ROWTYPE;
    app_evidence_changed BOOLEAN;
    verifier_evidence_changed BOOLEAN;
    policy_evidence_changed BOOLEAN;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'GitHub provider manifest current pointers cannot be removed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_current_removal_forbidden';
    END IF;

    IF TG_OP = 'INSERT' THEN
        SELECT * INTO STRICT replacement
        FROM github_provider_manifest_revisions
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND provider_connection_id = NEW.provider_connection_id
          AND manifest_revision = NEW.manifest_revision
          AND manifest_digest = NEW.manifest_digest;

        IF NEW.manifest_revision <> 1 THEN
            RAISE EXCEPTION 'initial GitHub provider manifest revision must be one'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_provider_manifest_current_initial_revision';
        ELSIF NEW.activated_at_ms <> replacement.registered_at_ms THEN
            RAISE EXCEPTION 'GitHub provider manifest activation must equal registration'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_provider_manifest_current_time';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR (CASE
            WHEN OLD.manifest_revision = 9223372036854775807 THEN TRUE
            ELSE NEW.manifest_revision <> OLD.manifest_revision + 1
        END)
        OR NEW.manifest_digest IS NOT DISTINCT FROM OLD.manifest_digest
        OR NEW.activated_at_ms < OLD.activated_at_ms
    THEN
        RAISE EXCEPTION 'GitHub provider manifest current transition is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_current_transition';
    END IF;

    SELECT * INTO STRICT prior
    FROM github_provider_manifest_revisions
    WHERE tenant_id = OLD.tenant_id
      AND repository_id = OLD.repository_id
      AND provider_connection_id = OLD.provider_connection_id
      AND manifest_revision = OLD.manifest_revision
      AND manifest_digest = OLD.manifest_digest;

    SELECT * INTO STRICT replacement
    FROM github_provider_manifest_revisions
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND provider_connection_id = NEW.provider_connection_id
      AND manifest_revision = NEW.manifest_revision
      AND manifest_digest = NEW.manifest_digest;

    IF NEW.activated_at_ms <> replacement.registered_at_ms THEN
        RAISE EXCEPTION 'GitHub provider manifest activation must equal registration'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_current_time';
    END IF;

    IF replacement.repository_id IS DISTINCT FROM prior.repository_id
        OR replacement.provider_installation_id IS DISTINCT FROM prior.provider_installation_id
        OR replacement.github_repository_id IS DISTINCT FROM prior.github_repository_id
        OR replacement.github_repository_name IS DISTINCT FROM prior.github_repository_name
        OR replacement.github_app_id IS DISTINCT FROM prior.github_app_id
        OR replacement.github_app_client_id IS DISTINCT FROM prior.github_app_client_id
        OR replacement.github_app_jwt_issuer_kind IS DISTINCT FROM prior.github_app_jwt_issuer_kind
        OR replacement.github_web_origin IS DISTINCT FROM prior.github_web_origin
        OR replacement.github_api_origin IS DISTINCT FROM prior.github_api_origin
        OR replacement.github_archive_origin IS DISTINCT FROM prior.github_archive_origin
    THEN
        RAISE EXCEPTION 'GitHub provider manifest connection identity changed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_connection_immutable';
    END IF;

    app_evidence_changed =
        replacement.app_key_spki_sha256 IS DISTINCT FROM prior.app_key_spki_sha256;
    verifier_evidence_changed =
        replacement.webhook_verifier_fingerprint_sha256
            IS DISTINCT FROM prior.webhook_verifier_fingerprint_sha256;
    policy_evidence_changed =
        replacement.repository_visibility IS DISTINCT FROM prior.repository_visibility
        OR replacement.authority_profile IS DISTINCT FROM prior.authority_profile
        OR replacement.workflow_path IS DISTINCT FROM prior.workflow_path
        OR replacement.event_name IS DISTINCT FROM prior.event_name
        OR replacement.git_ref IS DISTINCT FROM prior.git_ref
        OR replacement.check_subject_key IS DISTINCT FROM prior.check_subject_key
        OR replacement.check_name IS DISTINCT FROM prior.check_name
        OR replacement.github_rest_api_version IS DISTINCT FROM prior.github_rest_api_version
        OR replacement.github_rest_accept IS DISTINCT FROM prior.github_rest_accept
        OR replacement.github_archive_accept IS DISTINCT FROM prior.github_archive_accept
        OR replacement.repository_source_authentication
            IS DISTINCT FROM prior.repository_source_authentication
        OR replacement.repository_source_revision IS DISTINCT FROM prior.repository_source_revision
        OR replacement.repository_archive_format IS DISTINCT FROM prior.repository_archive_format
        OR replacement.webhook_max_body_bytes IS DISTINCT FROM prior.webhook_max_body_bytes
        OR replacement.webhook_accept_timeout_ms IS DISTINCT FROM prior.webhook_accept_timeout_ms
        OR replacement.push_webhook_max_commits IS DISTINCT FROM prior.push_webhook_max_commits
        OR replacement.path_filter_max_commits IS DISTINCT FROM prior.path_filter_max_commits
        OR replacement.path_filter_max_changed_files
            IS DISTINCT FROM prior.path_filter_max_changed_files
        OR replacement.archive_max_compressed_bytes IS DISTINCT FROM prior.archive_max_compressed_bytes
        OR replacement.archive_max_decompressed_bytes IS DISTINCT FROM prior.archive_max_decompressed_bytes
        OR replacement.archive_max_entries IS DISTINCT FROM prior.archive_max_entries
        OR replacement.archive_max_expanded_bytes IS DISTINCT FROM prior.archive_max_expanded_bytes
        OR replacement.archive_max_entry_path_bytes IS DISTINCT FROM prior.archive_max_entry_path_bytes
        OR replacement.archive_max_workflows IS DISTINCT FROM prior.archive_max_workflows
        OR replacement.workflow_max_bytes IS DISTINCT FROM prior.workflow_max_bytes;

    IF NOT (app_evidence_changed OR verifier_evidence_changed OR policy_evidence_changed)
        OR (CASE
            WHEN app_evidence_changed THEN
                prior.app_configuration_revision = 9223372036854775807
                OR replacement.app_configuration_revision
                    <> prior.app_configuration_revision + 1
            ELSE replacement.app_configuration_revision
                <> prior.app_configuration_revision
        END)
        OR (CASE
            WHEN verifier_evidence_changed THEN
                prior.webhook_verifier_revision = 9223372036854775807
                OR replacement.webhook_verifier_revision
                    <> prior.webhook_verifier_revision + 1
            ELSE replacement.webhook_verifier_revision
                <> prior.webhook_verifier_revision
        END)
        OR (CASE
            WHEN policy_evidence_changed THEN
                prior.policy_revision = 9223372036854775807
                OR replacement.policy_revision <> prior.policy_revision + 1
            ELSE replacement.policy_revision <> prior.policy_revision
        END)
    THEN
        RAISE EXCEPTION 'GitHub provider manifest policy revision did not advance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_revision_transition';
    END IF;

    RETURN NEW;
END;
$automata$;

ALTER TABLE workflow_plan_v2_jobs
    ADD COLUMN authority_profile TEXT COLLATE "C",
    ADD CONSTRAINT workflow_plan_v2_jobs_authority_profile CHECK (
        authority_profile IS NULL
        OR authority_profile IN ('standard', 'credential_free')
    );

ALTER TABLE workflow_plan_v2_activation_preparation_claims
    ADD COLUMN authority_profile TEXT COLLATE "C" NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_activation_preparation_claims_authority_profile CHECK (
        authority_profile IN ('standard', 'credential_free')
    );

ALTER TABLE workflow_plan_v2_activation_preparations
    ADD COLUMN authority_profile TEXT COLLATE "C" NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_activation_preparations_authority_profile CHECK (
        authority_profile IN ('standard', 'credential_free')
    );

ALTER TABLE workflow_plan_v2_activation_publications
    ADD COLUMN authority_profile TEXT COLLATE "C" NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_activation_publications_authority_profile CHECK (
        authority_profile IN ('standard', 'credential_free')
    );

ALTER TABLE workflow_plan_v2_materialization_claims
    ADD COLUMN authority_profile TEXT COLLATE "C" NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_materialization_claims_authority_profile CHECK (
        authority_profile IN ('standard', 'credential_free')
    );

ALTER TABLE workflow_plan_v2_concrete_jobs
    ADD COLUMN authority_profile TEXT COLLATE "C" NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_concrete_jobs_authority_profile CHECK (
        authority_profile IN ('standard', 'credential_free')
    );

CREATE FUNCTION automata_validate_activation_preparation_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN github_workflow_run_subject_evidence AS subject
          ON subject.tenant_id = repository.tenant_id
         AND subject.repository_id = run.repository_id
         AND subject.run_id = run.id
         AND subject.root_invocation_id = NEW.invocation_id
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery.tenant_id
         AND manifest.repository_id = delivery.repository_id
         AND manifest.provider_connection_id = delivery.provider_connection_id
         AND manifest.manifest_revision = delivery.provider_manifest_revision
         AND manifest.manifest_digest = delivery.provider_manifest_digest
        WHERE run.id = NEW.run_id
          AND manifest.authority_profile = NEW.authority_profile
    ) THEN
        RAISE EXCEPTION 'logical activation preparation lacks exact historical authority profile'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_activation_preparation_historical_profile';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparation_claims_00_profile
BEFORE INSERT ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW EXECUTE FUNCTION automata_validate_activation_preparation_authority_profile();

CREATE FUNCTION automata_enforce_preparation_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.authority_profile IS DISTINCT FROM OLD.authority_profile THEN
        RAISE EXCEPTION 'logical activation preparation authority profile is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_activation_preparation_profile_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparation_claims_profile_immutable
BEFORE UPDATE ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW EXECUTE FUNCTION automata_enforce_preparation_authority_profile();

CREATE FUNCTION automata_enforce_logical_job_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.authority_profile IS NOT NULL
        AND NEW.authority_profile IS DISTINCT FROM OLD.authority_profile
    THEN
        RAISE EXCEPTION 'logical job authority profile is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_jobs_authority_profile_immutable';
    END IF;
    IF OLD.authority_profile IS NULL AND NEW.authority_profile IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_activation_preparation_claims AS claim
            WHERE claim.logical_job_id = NEW.id
              AND claim.run_id = NEW.run_id
              AND claim.invocation_id = NEW.invocation_id
              AND claim.authority_profile = NEW.authority_profile
        )
    THEN
        RAISE EXCEPTION 'logical job authority profile lacks exact preparation claim'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_jobs_authority_profile_binding';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_enforce_authority_profile
BEFORE UPDATE ON workflow_plan_v2_jobs
FOR EACH ROW EXECUTE FUNCTION automata_enforce_logical_job_authority_profile();

CREATE FUNCTION automata_validate_prepared_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_preparation_claims AS claim
        JOIN workflow_plan_v2_jobs AS job ON job.id = claim.logical_job_id
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.authority_profile = NEW.authority_profile
          AND job.authority_profile = NEW.authority_profile
    ) THEN
        RAISE EXCEPTION 'prepared activation authority profile is inconsistent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_activation_preparations_profile_binding';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparations_00_profile
BEFORE INSERT ON workflow_plan_v2_activation_preparations
FOR EACH ROW EXECUTE FUNCTION automata_validate_prepared_authority_profile();

CREATE OR REPLACE FUNCTION automata_enforce_workflow_plan_v2_activation_input()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.activation_input_digest IS NOT NULL
        AND NEW.activation_input_digest IS DISTINCT FROM OLD.activation_input_digest
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 activation input digest is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.state = 'activating' AND NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_preparations AS preparation
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.state = 'prepared'
        WHERE preparation.run_id = NEW.run_id
          AND preparation.invocation_id = NEW.invocation_id
          AND preparation.logical_job_id = NEW.id
          AND preparation.activation_input_digest = NEW.activation_input_digest
          AND preparation.authority_profile = NEW.authority_profile
          AND preparation_claim.authority_profile = NEW.authority_profile
          AND preparation.bound_at_ms <= NEW.activation_claimed_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 activation input lacks exact profiled preparation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_validate_activation_publication_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.logical_job_id = job.id
         AND preparation.run_id = job.run_id
         AND preparation.invocation_id = job.invocation_id
        WHERE job.id = NEW.logical_job_id
          AND job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.authority_profile = NEW.authority_profile
          AND preparation.authority_profile = NEW.authority_profile
          AND preparation.activation_input_digest = NEW.activation_input_digest
    ) THEN
        RAISE EXCEPTION 'activation publication authority profile is inconsistent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_activation_publications_profile_binding';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_publications_00_profile
BEFORE INSERT ON workflow_plan_v2_activation_publications
FOR EACH ROW EXECUTE FUNCTION automata_validate_activation_publication_authority_profile();

CREATE FUNCTION automata_validate_materialization_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_instances AS instance
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        WHERE instance.id = NEW.instance_id
          AND instance.run_id = NEW.run_id
          AND instance.invocation_id = NEW.invocation_id
          AND instance.logical_job_id = NEW.logical_job_id
          AND publication.authority_profile = NEW.authority_profile
    ) THEN
        RAISE EXCEPTION 'materialization claim authority profile is inconsistent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_materialization_claims_profile_binding';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_materialization_claims_00_profile
BEFORE INSERT ON workflow_plan_v2_materialization_claims
FOR EACH ROW EXECUTE FUNCTION automata_validate_materialization_authority_profile();

CREATE FUNCTION automata_enforce_materialization_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.authority_profile IS DISTINCT FROM OLD.authority_profile THEN
        RAISE EXCEPTION 'materialization authority profile is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_materialization_claims_profile_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_materialization_claims_profile_immutable
BEFORE UPDATE ON workflow_plan_v2_materialization_claims
FOR EACH ROW EXECUTE FUNCTION automata_enforce_materialization_authority_profile();

CREATE FUNCTION automata_validate_concrete_job_authority_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_materialization_claims AS claim
        WHERE claim.instance_id = NEW.instance_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.authority_profile = NEW.authority_profile
    ) THEN
        RAISE EXCEPTION 'concrete job authority profile is inconsistent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_concrete_jobs_profile_binding';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_concrete_jobs_00_profile
BEFORE INSERT ON workflow_plan_v2_concrete_jobs
FOR EACH ROW EXECUTE FUNCTION automata_validate_concrete_job_authority_profile();

CREATE OR REPLACE FUNCTION automata_github_runtime_authority_is_current(
    authority github_runtime_authority_issuances,
    observed_at BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT EXISTS (
        SELECT 1
        FROM job_attempts AS attempt
        JOIN jobs AS job
          ON job.id = attempt.job_id
         AND job.id = authority.job_id
         AND job.run_id = authority.run_id
        JOIN workflow_runs AS run
          ON run.id = job.run_id
         AND run.id = authority.run_id
         AND run.repository_id = authority.repository_id
        JOIN repositories AS repository
          ON repository.id = run.repository_id
         AND repository.id = authority.repository_id
         AND repository.tenant_id = authority.tenant_id
        JOIN workflow_definitions AS workflow
          ON workflow.id = run.workflow_id
         AND workflow.repository_id = run.repository_id
        JOIN workflow_snapshots AS snapshot
          ON snapshot.id = run.snapshot_id
         AND snapshot.workflow_id = run.workflow_id
        JOIN workflow_plan_v2_runs AS marker
          ON marker.run_id = run.id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = run.id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = run.id
         AND logical_job.invocation_id = invocation.id
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = logical_job.run_id
         AND preparation_claim.invocation_id = logical_job.invocation_id
         AND preparation_claim.logical_job_id = logical_job.id
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.run_id = preparation_claim.run_id
         AND preparation.invocation_id = preparation_claim.invocation_id
         AND preparation.logical_job_id = preparation_claim.logical_job_id
         AND preparation.descriptor_digest = preparation_claim.descriptor_digest
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = logical_job.run_id
         AND publication.invocation_id = logical_job.invocation_id
         AND publication.logical_job_id = logical_job.id
         AND publication.activation_input_digest = preparation.activation_input_digest
        JOIN workflow_plan_v2_instances AS instance
          ON instance.run_id = publication.run_id
         AND instance.invocation_id = publication.invocation_id
         AND instance.logical_job_id = publication.logical_job_id
        JOIN workflow_plan_v2_materialization_claims AS materialization
          ON materialization.instance_id = instance.id
         AND materialization.run_id = instance.run_id
         AND materialization.invocation_id = instance.invocation_id
         AND materialization.logical_job_id = instance.logical_job_id
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.instance_id = materialization.instance_id
         AND concrete.run_id = materialization.run_id
         AND concrete.invocation_id = materialization.invocation_id
         AND concrete.logical_job_id = materialization.logical_job_id
         AND concrete.descriptor_digest = materialization.descriptor_digest
         AND concrete.job_id = materialization.expected_job_id
         AND concrete.initial_attempt_id = materialization.expected_attempt_id
         AND concrete.claim_owner_id = materialization.owner_id
         AND concrete.claim_generation = materialization.generation
         AND concrete.claim_started_at_ms = materialization.claimed_at_ms
         AND concrete.claim_expires_at_ms = materialization.expires_at_ms
         AND concrete.committed_at_ms = materialization.updated_at_ms
         AND concrete.job_id = job.id
        JOIN github_workflow_run_subject_evidence AS subject
          ON subject.tenant_id = repository.tenant_id
         AND subject.repository_id = repository.id
         AND subject.workflow_id = run.workflow_id
         AND subject.run_id = run.id
         AND subject.root_invocation_id = invocation.id
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        JOIN workflow_admission_receipts AS admission_receipt
          ON admission_receipt.tenant_id = subject.tenant_id
         AND admission_receipt.idempotency_kind = 'provider_delivery'
         AND admission_receipt.idempotency_key = subject.provider_delivery_idempotency_key
         AND admission_receipt.request_digest = subject.logical_admission_digest
         AND admission_receipt.repository_id = subject.repository_id
         AND admission_receipt.run_id = subject.run_id
         AND admission_receipt.committed_at_ms = subject.admitted_at_ms
         AND admission_receipt.github_subject_evidence_required
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery.tenant_id
         AND manifest.repository_id = delivery.repository_id
         AND manifest.provider_connection_id = delivery.provider_connection_id
         AND manifest.manifest_revision = delivery.provider_manifest_revision
         AND manifest.manifest_digest = delivery.provider_manifest_digest
        JOIN github_server_service_authorities AS checks_authority
          ON checks_authority.tenant_id = delivery.tenant_id
         AND checks_authority.id = delivery.checks_authority_id
         AND checks_authority.repository_id = delivery.repository_id
         AND checks_authority.provider_connection_id = delivery.provider_connection_id
         AND checks_authority.provider_installation_id = delivery.provider_installation_id
         AND checks_authority.github_repository_id = delivery.github_repository_id
         AND checks_authority.github_repository_name = delivery.github_repository_name
         AND checks_authority.service_scope = 'checks_write'
         AND checks_authority.identity_digest = delivery.checks_authority_identity_digest
         AND checks_authority.app_configuration_revision =
             delivery.checks_authority_app_configuration_revision
         AND checks_authority.policy_revision = delivery.checks_authority_policy_revision
        LEFT JOIN github_server_service_authorities AS private_authority
          ON private_authority.tenant_id = delivery.tenant_id
         AND private_authority.id = delivery.private_source_authority_id
         AND private_authority.repository_id = delivery.repository_id
         AND private_authority.provider_connection_id = delivery.provider_connection_id
         AND private_authority.provider_installation_id = delivery.provider_installation_id
         AND private_authority.github_repository_id = delivery.github_repository_id
         AND private_authority.github_repository_name = delivery.github_repository_name
         AND private_authority.service_scope = 'private_repository_source_read'
         AND private_authority.identity_digest = delivery.private_source_authority_identity_digest
         AND private_authority.app_configuration_revision =
             delivery.private_source_authority_app_configuration_revision
         AND private_authority.policy_revision = delivery.private_source_authority_policy_revision
        JOIN runners AS runner
          ON runner.id = attempt.runner_id
         AND runner.id = authority.runner_id
         AND runner.tenant_id = authority.tenant_id
         AND runner.generation = authority.runner_generation
         AND runner.session_epoch = authority.runner_session_epoch
        JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.id = authority.runner_session_id
         AND session.runner_id = authority.runner_id
         AND session.session_epoch = authority.runner_session_epoch
         AND session.runner_generation = authority.runner_generation
        WHERE attempt.id = authority.attempt_id
          AND attempt.job_id = authority.job_id
          AND attempt.fencing_token = authority.fencing_token
          AND attempt.lease_id = authority.lease_id
          AND attempt.lease_issued_at_ms = authority.lease_issued_at_ms
          AND attempt.lease_expires_at_ms = authority.lease_expires_at_ms
          AND attempt.lease_expires_at_ms > observed_at
          AND attempt.runner_id = authority.runner_id
          AND attempt.runner_session_id = authority.runner_session_id
          AND attempt.runner_session_epoch = authority.runner_session_epoch
          AND attempt.runner_generation = authority.runner_generation
          AND attempt.runner_slot = authority.runner_slot
          AND attempt.lifecycle IN ('leased', 'preparing', 'running')
          AND attempt.changed_at_ms <= observed_at
          AND job.admission_epoch = 4
          AND job.job_ir_schema = 5
          AND job.job_ir_schema = authority.job_ir_schema
          AND job.job_ir_size_bytes = authority.job_ir_size_bytes
          AND job.job_ir_digest = authority.job_ir_digest
          AND job.job_ir_digest = authority.policy_digest
          AND concrete.requirements = job.requirements
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND run.plan_digest = invocation.plan_digest
          AND run.plan_digest = subject.plan_digest
          AND run.event_digest = subject.event_digest
          AND run.head_sha = subject.github_check_head_sha
          AND run.event_name = subject.event_name
          AND run.git_ref = subject.git_ref
          AND run.status IN ('queued', 'in_progress')
          AND workflow.path = subject.workflow_path
          AND snapshot.source_digest = subject.source_digest
          AND marker.orchestration_schema = 1
          AND marker.admission_digest = subject.logical_admission_digest
          AND marker.admitted_at_ms = subject.admitted_at_ms
          AND marker.state IN ('pending', 'active')
          AND invocation.plan_schema = 2
          AND invocation.plan_digest = subject.plan_digest
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND logical_job.activation_input_digest = preparation.activation_input_digest
          AND preparation_claim.state = 'prepared'
          AND publication.condition_matched
          AND publication.job_ir_version = 5
          AND publication.runtime_context_schema = 2
          AND instance.job_ir_version = 5
          AND instance.job_ir_digest = job.job_ir_digest
          AND instance.job_ir_size_bytes = job.job_ir_size_bytes
          AND instance.job_ir_object_key = job.job_ir_object_key
          AND instance.job_ir_media_type = 'application/vnd.automata.job-ir.protobuf'
          AND materialization.state = 'materialized'
          AND concrete.runtime_context_schema = 2
          AND manifest.authority_profile = 'standard'
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND publication.authority_profile = 'standard'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id = delivery.github_repository_id::TEXT
          AND repository.owner || '/' || repository.name = delivery.github_repository_name
          AND authority.provider_connection_id = delivery.provider_connection_id
          AND authority.provider_connection_id = manifest.provider_connection_id
          AND authority.provider_installation_id = delivery.provider_installation_id
          AND authority.provider_installation_id = manifest.provider_installation_id
          AND authority.github_repository_id = delivery.github_repository_id
          AND authority.github_repository_id = manifest.github_repository_id
          AND authority.github_repository_name = delivery.github_repository_name
          AND authority.github_repository_name = manifest.github_repository_name
          AND authority.authority_namespace = 'github.repository'
          AND authority.issuer_fingerprint = manifest.app_key_spki_sha256
          AND authority.configuration_fingerprint =
              checks_authority.configuration_fingerprint
          AND authority.requested_at_ms = attempt.lease_issued_at_ms
          AND authority.request_deadline_at_ms = LEAST(
              attempt.lease_expires_at_ms,
              attempt.lease_issued_at_ms + 120000
          )
          AND manifest.webhook_verifier_fingerprint_sha256 =
              delivery.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              delivery.authenticated_webhook_verifier_revision
          AND manifest.repository_visibility = delivery.repository_visibility
          AND manifest.github_web_origin = 'https://github.com/'
          AND manifest.github_api_origin = 'https://api.github.com/'
          AND manifest.github_rest_api_version = '2026-03-10'
          AND manifest.github_app_id = checks_authority.github_app_id
          AND manifest.github_app_client_id = checks_authority.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind =
              checks_authority.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = checks_authority.app_key_spki_sha256
          AND manifest.app_configuration_revision =
              checks_authority.app_configuration_revision
          AND manifest.policy_revision = checks_authority.policy_revision
          AND manifest.registered_at_ms <= observed_at
          AND checks_authority.state = 'active'
          AND checks_authority.created_at_ms <= observed_at
          AND checks_authority.state_updated_at_ms <= observed_at
          AND (
              delivery.repository_visibility = 'public'
              AND delivery.private_source_authority_id IS NULL
              AND private_authority.id IS NULL
              OR delivery.repository_visibility = 'private'
              AND private_authority.id IS NOT NULL
              AND private_authority.github_app_id = manifest.github_app_id
              AND private_authority.github_app_client_id = manifest.github_app_client_id
              AND private_authority.github_app_jwt_issuer_kind =
                  manifest.github_app_jwt_issuer_kind
              AND private_authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
              AND private_authority.app_configuration_revision =
                  manifest.app_configuration_revision
              AND private_authority.policy_revision = manifest.policy_revision
              AND private_authority.state = 'active'
              AND private_authority.created_at_ms <= observed_at
              AND private_authority.state_updated_at_ms <= observed_at
          )
          AND subject.admitted_at_ms <= observed_at
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND session.job_ir_schema = 5
          AND session.disconnected_at_ms IS NULL
    )
$automata$;

-- Lock the same immutable historical dependency graph before OIDC reservation.
CREATE OR REPLACE FUNCTION automata_lock_github_oidc_authority_dependencies(
    authority github_oidc_authorities
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $automata$
DECLARE
    delivery_visibility TEXT;
    private_authority_id UUID;
BEGIN
    SELECT delivery_evidence.repository_visibility,
           delivery_evidence.private_source_authority_id
      INTO delivery_visibility, private_authority_id
    FROM job_attempts AS attempt
    JOIN jobs AS job
      ON job.id = attempt.job_id
     AND job.id = authority.job_id
     AND job.run_id = authority.run_id
    JOIN workflow_runs AS run
      ON run.id = job.run_id
     AND run.id = authority.run_id
     AND run.repository_id = authority.repository_id
    JOIN repositories AS repository
      ON repository.id = run.repository_id
     AND repository.tenant_id = authority.tenant_id
    JOIN workflow_definitions AS workflow
      ON workflow.id = run.workflow_id
     AND workflow.repository_id = run.repository_id
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
    JOIN workflow_plan_v2_invocations AS invocation
      ON invocation.run_id = run.id
     AND invocation.id = authority.invocation_id
    JOIN workflow_plan_v2_jobs AS logical_job
      ON logical_job.run_id = run.id
     AND logical_job.invocation_id = invocation.id
     AND logical_job.id = authority.logical_job_id
    JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
      ON preparation_claim.run_id = logical_job.run_id
     AND preparation_claim.invocation_id = logical_job.invocation_id
     AND preparation_claim.logical_job_id = logical_job.id
    JOIN workflow_plan_v2_activation_preparations AS preparation
      ON preparation.run_id = preparation_claim.run_id
     AND preparation.invocation_id = preparation_claim.invocation_id
     AND preparation.logical_job_id = preparation_claim.logical_job_id
     AND preparation.descriptor_digest = preparation_claim.descriptor_digest
    JOIN workflow_plan_v2_activation_publications AS publication
      ON publication.run_id = logical_job.run_id
     AND publication.invocation_id = logical_job.invocation_id
     AND publication.logical_job_id = logical_job.id
     AND publication.activation_input_digest = preparation.activation_input_digest
    JOIN workflow_plan_v2_instances AS instance
      ON instance.run_id = run.id
     AND instance.invocation_id = invocation.id
     AND instance.logical_job_id = logical_job.id
     AND instance.id = authority.instance_id
    JOIN workflow_plan_v2_concrete_jobs AS concrete
      ON concrete.instance_id = instance.id
     AND concrete.run_id = run.id
     AND concrete.invocation_id = invocation.id
     AND concrete.logical_job_id = logical_job.id
     AND concrete.job_id = job.id
    JOIN workflow_plan_v2_materialization_claims AS materialization
      ON materialization.instance_id = concrete.instance_id
     AND materialization.run_id = concrete.run_id
     AND materialization.invocation_id = concrete.invocation_id
     AND materialization.logical_job_id = concrete.logical_job_id
     AND materialization.descriptor_digest = concrete.descriptor_digest
     AND materialization.expected_job_id = concrete.job_id
     AND materialization.expected_attempt_id = concrete.initial_attempt_id
     AND materialization.owner_id = concrete.claim_owner_id
     AND materialization.generation = concrete.claim_generation
     AND materialization.claimed_at_ms = concrete.claim_started_at_ms
     AND materialization.expires_at_ms = concrete.claim_expires_at_ms
     AND materialization.updated_at_ms = concrete.committed_at_ms
    JOIN runners AS runner
      ON runner.id = attempt.runner_id
     AND runner.id = authority.runner_id
     AND runner.tenant_id = authority.tenant_id
    JOIN runner_sessions AS session
      ON session.id = attempt.runner_session_id
     AND session.id = authority.runner_session_id
     AND session.runner_id = authority.runner_id
    JOIN github_workflow_run_subject_evidence AS subject_evidence
      ON subject_evidence.tenant_id = authority.tenant_id
     AND subject_evidence.repository_id = authority.repository_id
     AND subject_evidence.workflow_id = authority.workflow_id
     AND subject_evidence.run_id = authority.run_id
     AND subject_evidence.root_invocation_id = authority.invocation_id
     AND subject_evidence.subject_evidence_sha256 =
         authority.github_run_subject_evidence_sha256
    JOIN github_provider_delivery_evidence AS delivery_evidence
      ON delivery_evidence.tenant_id = subject_evidence.tenant_id
     AND delivery_evidence.repository_id = subject_evidence.repository_id
     AND delivery_evidence.provider_delivery_id =
         subject_evidence.provider_delivery_id
    JOIN workflow_admission_receipts AS admission_receipt
      ON admission_receipt.tenant_id = subject_evidence.tenant_id
     AND admission_receipt.idempotency_kind = 'provider_delivery'
     AND admission_receipt.idempotency_key =
         subject_evidence.provider_delivery_idempotency_key
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = delivery_evidence.tenant_id
     AND manifest.repository_id = delivery_evidence.repository_id
     AND manifest.provider_connection_id =
         delivery_evidence.provider_connection_id
     AND manifest.manifest_revision =
         delivery_evidence.provider_manifest_revision
     AND manifest.manifest_digest = delivery_evidence.provider_manifest_digest
    JOIN github_server_service_authorities AS checks_authority
      ON checks_authority.tenant_id = delivery_evidence.tenant_id
     AND checks_authority.id = delivery_evidence.checks_authority_id
     AND checks_authority.identity_digest =
         delivery_evidence.checks_authority_identity_digest
     AND checks_authority.app_configuration_revision =
         delivery_evidence.checks_authority_app_configuration_revision
     AND checks_authority.policy_revision =
         delivery_evidence.checks_authority_policy_revision
    WHERE attempt.id = authority.attempt_id
      AND materialization.state = 'materialized'
      AND logical_job.activation_input_digest = preparation.activation_input_digest
      AND preparation_claim.state = 'prepared'
      AND publication.condition_matched
      AND manifest.authority_profile = 'standard'
      AND logical_job.authority_profile = 'standard'
      AND preparation_claim.authority_profile = 'standard'
      AND preparation.authority_profile = 'standard'
      AND publication.authority_profile = 'standard'
      AND materialization.authority_profile = 'standard'
      AND concrete.authority_profile = 'standard'
      AND checks_authority.state = 'active'
    FOR SHARE OF attempt, job, run, repository, workflow, snapshot, marker,
                 invocation, logical_job, preparation_claim, preparation,
                 publication, instance, concrete, materialization,
                 runner, session,
                 subject_evidence, delivery_evidence, admission_receipt,
                 manifest, checks_authority;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF delivery_visibility = 'public' THEN
        RETURN private_authority_id IS NULL;
    END IF;
    IF delivery_visibility <> 'private' OR private_authority_id IS NULL THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM github_provider_delivery_evidence AS delivery_evidence
    JOIN github_server_service_authorities AS private_authority
      ON private_authority.tenant_id = delivery_evidence.tenant_id
     AND private_authority.id = delivery_evidence.private_source_authority_id
     AND private_authority.repository_id = delivery_evidence.repository_id
     AND private_authority.provider_connection_id =
         delivery_evidence.provider_connection_id
     AND private_authority.provider_installation_id =
         delivery_evidence.provider_installation_id
     AND private_authority.github_repository_id =
         delivery_evidence.github_repository_id
     AND private_authority.github_repository_name =
         delivery_evidence.github_repository_name
     AND private_authority.service_scope = 'private_repository_source_read'
     AND private_authority.identity_digest =
         delivery_evidence.private_source_authority_identity_digest
     AND private_authority.app_configuration_revision =
         delivery_evidence.private_source_authority_app_configuration_revision
     AND private_authority.policy_revision =
         delivery_evidence.private_source_authority_policy_revision
    WHERE delivery_evidence.tenant_id = authority.tenant_id
      AND delivery_evidence.repository_id = authority.repository_id
      AND delivery_evidence.private_source_authority_id = private_authority_id
      AND private_authority.state = 'active'
    FOR SHARE OF private_authority;
    RETURN FOUND;
END;
$automata$;

-- OIDC currentness remains bound to the immutable delivery manifest revision.
-- A later current-pointer rotation cannot grant or revoke this run's profile.
CREATE OR REPLACE FUNCTION automata_github_oidc_authority_is_current(
    authority github_oidc_authorities,
    observed_at_ms BIGINT,
    required_current_before_ms BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT EXISTS (
        SELECT 1
        FROM job_attempts AS attempt
        JOIN jobs AS job
          ON job.id = attempt.job_id
         AND job.id = authority.job_id
         AND job.run_id = authority.run_id
        JOIN workflow_runs AS run
          ON run.id = job.run_id
         AND run.id = authority.run_id
         AND run.repository_id = authority.repository_id
         AND run.workflow_id = authority.workflow_id
        JOIN repositories AS repository
          ON repository.id = run.repository_id
         AND repository.id = authority.repository_id
         AND repository.tenant_id = authority.tenant_id
        JOIN workflow_definitions AS workflow
          ON workflow.id = run.workflow_id
         AND workflow.repository_id = run.repository_id
        JOIN workflow_snapshots AS snapshot
          ON snapshot.id = run.snapshot_id
         AND snapshot.workflow_id = run.workflow_id
        JOIN workflow_plan_v2_runs AS marker
          ON marker.run_id = run.id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = run.id
         AND invocation.id = authority.invocation_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = run.id
         AND logical_job.invocation_id = invocation.id
         AND logical_job.id = authority.logical_job_id
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = logical_job.run_id
         AND preparation_claim.invocation_id = logical_job.invocation_id
         AND preparation_claim.logical_job_id = logical_job.id
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.run_id = preparation_claim.run_id
         AND preparation.invocation_id = preparation_claim.invocation_id
         AND preparation.logical_job_id = preparation_claim.logical_job_id
         AND preparation.descriptor_digest = preparation_claim.descriptor_digest
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = logical_job.run_id
         AND publication.invocation_id = logical_job.invocation_id
         AND publication.logical_job_id = logical_job.id
         AND publication.activation_input_digest = preparation.activation_input_digest
        JOIN workflow_plan_v2_instances AS instance
          ON instance.run_id = run.id
         AND instance.invocation_id = invocation.id
         AND instance.logical_job_id = logical_job.id
         AND instance.id = authority.instance_id
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.instance_id = instance.id
         AND concrete.run_id = run.id
         AND concrete.invocation_id = invocation.id
         AND concrete.logical_job_id = logical_job.id
         AND concrete.job_id = job.id
        JOIN workflow_plan_v2_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
         AND materialization.owner_id = concrete.claim_owner_id
         AND materialization.generation = concrete.claim_generation
         AND materialization.claimed_at_ms = concrete.claim_started_at_ms
         AND materialization.expires_at_ms = concrete.claim_expires_at_ms
         AND materialization.updated_at_ms = concrete.committed_at_ms
        JOIN runners AS runner
          ON runner.id = attempt.runner_id
         AND runner.id = authority.runner_id
         AND runner.tenant_id = authority.tenant_id
         AND runner.generation = authority.runner_generation
         AND runner.session_epoch = authority.runner_session_epoch
        JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.id = authority.runner_session_id
         AND session.runner_id = authority.runner_id
         AND session.session_epoch = authority.runner_session_epoch
         AND session.runner_generation = authority.runner_generation
        JOIN github_workflow_run_subject_evidence AS subject_evidence
          ON subject_evidence.tenant_id = authority.tenant_id
         AND subject_evidence.repository_id = authority.repository_id
         AND subject_evidence.workflow_id = authority.workflow_id
         AND subject_evidence.run_id = authority.run_id
         AND subject_evidence.root_invocation_id = authority.invocation_id
         AND subject_evidence.subject_evidence_sha256 =
             authority.github_run_subject_evidence_sha256
        JOIN github_provider_delivery_evidence AS delivery_evidence
          ON delivery_evidence.tenant_id = subject_evidence.tenant_id
         AND delivery_evidence.repository_id = subject_evidence.repository_id
         AND delivery_evidence.provider_delivery_id =
             subject_evidence.provider_delivery_id
        JOIN workflow_admission_receipts AS admission_receipt
          ON admission_receipt.tenant_id = subject_evidence.tenant_id
         AND admission_receipt.idempotency_kind = 'provider_delivery'
         AND admission_receipt.idempotency_key =
             subject_evidence.provider_delivery_idempotency_key
         AND admission_receipt.request_digest =
             subject_evidence.logical_admission_digest
         AND admission_receipt.repository_id = subject_evidence.repository_id
         AND admission_receipt.run_id = subject_evidence.run_id
         AND admission_receipt.committed_at_ms = subject_evidence.admitted_at_ms
         AND admission_receipt.github_subject_evidence_required
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery_evidence.tenant_id
         AND manifest.repository_id = delivery_evidence.repository_id
         AND manifest.provider_connection_id =
             delivery_evidence.provider_connection_id
         AND manifest.manifest_revision =
             delivery_evidence.provider_manifest_revision
         AND manifest.manifest_digest = delivery_evidence.provider_manifest_digest
        JOIN github_server_service_authorities AS checks_authority
          ON checks_authority.tenant_id = delivery_evidence.tenant_id
         AND checks_authority.id = delivery_evidence.checks_authority_id
         AND checks_authority.repository_id = delivery_evidence.repository_id
         AND checks_authority.provider_connection_id =
             delivery_evidence.provider_connection_id
         AND checks_authority.provider_installation_id =
             delivery_evidence.provider_installation_id
         AND checks_authority.github_repository_id =
             delivery_evidence.github_repository_id
         AND checks_authority.github_repository_name =
             delivery_evidence.github_repository_name
         AND checks_authority.service_scope = 'checks_write'
         AND checks_authority.identity_digest =
             delivery_evidence.checks_authority_identity_digest
         AND checks_authority.app_configuration_revision =
             delivery_evidence.checks_authority_app_configuration_revision
         AND checks_authority.policy_revision =
             delivery_evidence.checks_authority_policy_revision
        LEFT JOIN github_server_service_authorities AS private_authority
          ON private_authority.tenant_id = delivery_evidence.tenant_id
         AND private_authority.id = delivery_evidence.private_source_authority_id
         AND private_authority.repository_id = delivery_evidence.repository_id
         AND private_authority.provider_connection_id =
             delivery_evidence.provider_connection_id
         AND private_authority.provider_installation_id =
             delivery_evidence.provider_installation_id
         AND private_authority.github_repository_id =
             delivery_evidence.github_repository_id
         AND private_authority.github_repository_name =
             delivery_evidence.github_repository_name
         AND private_authority.service_scope =
             'private_repository_source_read'
         AND private_authority.identity_digest =
             delivery_evidence.private_source_authority_identity_digest
         AND private_authority.app_configuration_revision =
             delivery_evidence.private_source_authority_app_configuration_revision
         AND private_authority.policy_revision =
             delivery_evidence.private_source_authority_policy_revision
        WHERE attempt.id = authority.attempt_id
          AND attempt.job_id = authority.job_id
          AND attempt.attempt_number = authority.attempt_number
          AND attempt.fencing_token = authority.fencing_token
          AND attempt.lease_id = authority.lease_id
          AND attempt.lease_issued_at_ms = authority.lease_issued_at_ms
          AND attempt.lease_expires_at_ms >= authority.lease_expires_at_ms
          AND required_current_before_ms > observed_at_ms
          AND attempt.lease_expires_at_ms >= required_current_before_ms
          AND attempt.runner_id = authority.runner_id
          AND attempt.runner_session_id = authority.runner_session_id
          AND attempt.runner_session_epoch = authority.runner_session_epoch
          AND attempt.runner_generation = authority.runner_generation
          AND attempt.runner_slot = authority.runner_slot
          AND attempt.lifecycle IN ('leased', 'preparing', 'running')
          AND attempt.changed_at_ms <= observed_at_ms
          AND job.admission_epoch = 4
          AND job.job_ir_schema = 5
          AND job.job_ir_schema = authority.job_ir_schema
          AND job.job_ir_size_bytes = authority.job_ir_size_bytes
          AND job.job_ir_digest = authority.job_ir_digest
          AND job.job_ir_object_key = authority.job_ir_object_key
          AND authority.permission_evidence_sha256 = authority.job_ir_digest
          AND job.requirements @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND run.plan_digest = authority.plan_digest
          AND run.plan_digest = subject_evidence.plan_digest
          AND run.event_digest = authority.event_digest
          AND run.event_digest = subject_evidence.event_digest
          AND run.snapshot_id = subject_evidence.snapshot_id
          AND run.head_sha = subject_evidence.github_check_head_sha
          AND run.event_name = subject_evidence.event_name
          AND run.git_ref = subject_evidence.git_ref
          AND run.status IN ('queued', 'in_progress')
          AND workflow.path = subject_evidence.workflow_path
          AND snapshot.source_digest = subject_evidence.source_digest
          AND marker.orchestration_schema = 1
          AND marker.root_invocation_id = subject_evidence.root_invocation_id
          AND marker.admission_digest = subject_evidence.logical_admission_digest
          AND marker.admitted_at_ms = subject_evidence.admitted_at_ms
          AND marker.state IN ('pending', 'active')
          AND invocation.plan_schema = 2
          AND invocation.plan_digest = authority.plan_digest
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND instance.job_ir_version = 5
          AND instance.job_ir_digest = authority.job_ir_digest
          AND instance.job_ir_object_key = authority.job_ir_object_key
          AND instance.job_ir_size_bytes = authority.job_ir_size_bytes
          AND concrete.runtime_context_schema = 2
          AND concrete.runtime_context_digest = authority.runtime_context_digest
          AND concrete.requirements = job.requirements
          AND materialization.state = 'materialized'
          AND logical_job.activation_input_digest = preparation.activation_input_digest
          AND preparation_claim.state = 'prepared'
          AND publication.condition_matched
          AND publication.job_ir_version = 5
          AND publication.runtime_context_schema = 2
          AND manifest.authority_profile = 'standard'
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND publication.authority_profile = 'standard'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id =
              delivery_evidence.github_repository_id::TEXT
          AND repository.owner || '/' || repository.name =
              delivery_evidence.github_repository_name
          AND authority.github_repository_id =
              delivery_evidence.github_repository_id
          AND authority.github_repository_name =
              delivery_evidence.github_repository_name
          AND authority.github_owner_id =
              delivery_evidence.github_repository_owner_id
          AND authority.subject_policy_mode = 'stable_owner_evidence'
          AND authority.subject_policy_revision > 0
          AND authority.subject = CASE
              WHEN subject_evidence.event_name = 'pull_request'
              THEN 'repo:' || delivery_evidence.github_repository_name ||
                   ':pull_request'
              ELSE 'repo:' || delivery_evidence.github_repository_name ||
                   ':ref:' || subject_evidence.git_ref
          END
          AND authority.default_audience = 'https://github.com/' ||
              split_part(delivery_evidence.github_repository_name, '/', 1)
          AND authority.additional_claims = jsonb_build_object(
              'event_name', subject_evidence.event_name,
              'ref', subject_evidence.git_ref,
              'repository', delivery_evidence.github_repository_name,
              'repository_owner',
                  split_part(delivery_evidence.github_repository_name, '/', 1),
              'run_attempt', run.run_attempt::TEXT,
              'run_number', run.run_number::TEXT,
              'runner_environment', 'self-hosted',
              'sha', encode(subject_evidence.github_check_head_sha, 'hex'),
              'workflow', run.workflow_name,
              'workflow_ref', delivery_evidence.github_repository_name || '/' ||
                  regexp_replace(
                      subject_evidence.workflow_path,
                      '^\.ci/workflows/', '.github/workflows/'
                  ) || '@' || subject_evidence.git_ref,
              'workflow_sha', encode(subject_evidence.github_check_head_sha, 'hex')
          )
          AND manifest.webhook_verifier_fingerprint_sha256 =
              delivery_evidence.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              delivery_evidence.authenticated_webhook_verifier_revision
          AND manifest.provider_installation_id =
              delivery_evidence.provider_installation_id
          AND manifest.github_repository_id =
              delivery_evidence.github_repository_id
          AND manifest.github_repository_name =
              delivery_evidence.github_repository_name
          AND manifest.repository_visibility =
              delivery_evidence.repository_visibility
          AND manifest.registered_at_ms <= observed_at_ms
          AND checks_authority.state = 'active'
          AND checks_authority.created_at_ms <= observed_at_ms
          AND checks_authority.state_updated_at_ms <= observed_at_ms
          AND (
              delivery_evidence.repository_visibility = 'public'
              AND delivery_evidence.private_source_authority_id IS NULL
              AND private_authority.id IS NULL
              OR delivery_evidence.repository_visibility = 'private'
              AND private_authority.id IS NOT NULL
              AND private_authority.state = 'active'
              AND private_authority.created_at_ms <= observed_at_ms
              AND private_authority.state_updated_at_ms <= observed_at_ms
          )
          AND subject_evidence.admitted_at_ms <= observed_at_ms
          AND authority.request_bearer_iat_seconds * 1000 <= observed_at_ms
          AND authority.request_bearer_exp_seconds * 1000 > observed_at_ms
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND runner.capabilities @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND session.job_ir_schema = 5
          AND session.capability_snapshot @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND session.disconnected_at_ms IS NULL
    )
$automata$;

CREATE FUNCTION automata_require_standard_github_oidc_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM github_workflow_run_subject_evidence AS subject
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery.tenant_id
         AND manifest.repository_id = delivery.repository_id
         AND manifest.provider_connection_id = delivery.provider_connection_id
         AND manifest.manifest_revision = delivery.provider_manifest_revision
         AND manifest.manifest_digest = delivery.provider_manifest_digest
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.instance_id = NEW.instance_id
         AND concrete.run_id = NEW.run_id
         AND concrete.invocation_id = NEW.invocation_id
         AND concrete.logical_job_id = NEW.logical_job_id
         AND concrete.job_id = NEW.job_id
         AND concrete.initial_attempt_id = NEW.attempt_id
        WHERE subject.tenant_id = NEW.tenant_id
          AND subject.repository_id = NEW.repository_id
          AND subject.run_id = NEW.run_id
          AND subject.root_invocation_id = NEW.invocation_id
          AND manifest.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
    ) THEN
        RAISE EXCEPTION 'GitHub-compatible OIDC requires historical Standard authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'github_oidc_historical_standard_authority';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_oidc_authorities_00_historical_standard_profile
BEFORE INSERT ON github_oidc_authorities
FOR EACH ROW EXECUTE FUNCTION automata_require_standard_github_oidc_profile();
