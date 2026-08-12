-- Permit a repository policy revision to advance solely to rotate its
-- manifest-pinned server-service authorities.  The revision remains strictly
-- contiguous and every other independent evidence revision remains exact.
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
    runtime_policy_changed BOOLEAN;
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
        OR OLD.manifest_revision = 9223372036854775807
        OR NEW.manifest_revision <> OLD.manifest_revision + 1
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

    app_evidence_changed = replacement.app_key_spki_sha256
        IS DISTINCT FROM prior.app_key_spki_sha256;
    verifier_evidence_changed = replacement.webhook_verifier_fingerprint_sha256
        IS DISTINCT FROM prior.webhook_verifier_fingerprint_sha256;
    runtime_policy_changed = replacement.runtime_policy_digest
        IS DISTINCT FROM prior.runtime_policy_digest;
    policy_evidence_changed =
        replacement.policy_revision IS DISTINCT FROM prior.policy_revision
        OR replacement.repository_visibility IS DISTINCT FROM prior.repository_visibility
        OR replacement.authority_profile IS DISTINCT FROM prior.authority_profile
        OR replacement.runner_policy_digest IS DISTINCT FROM prior.runner_policy_digest
        OR replacement.runner_policy_object_key IS DISTINCT FROM prior.runner_policy_object_key
        OR replacement.runner_policy_size_bytes IS DISTINCT FROM prior.runner_policy_size_bytes
        OR replacement.runner_policy_media_type IS DISTINCT FROM prior.runner_policy_media_type
        OR runtime_policy_changed
        OR replacement.workflow_path IS DISTINCT FROM prior.workflow_path
        OR replacement.event_name IS DISTINCT FROM prior.event_name
        OR replacement.git_ref IS DISTINCT FROM prior.git_ref
        OR replacement.check_subject_key IS DISTINCT FROM prior.check_subject_key
        OR replacement.check_name IS DISTINCT FROM prior.check_name
        OR replacement.github_rest_api_version IS DISTINCT FROM prior.github_rest_api_version
        OR replacement.github_rest_accept IS DISTINCT FROM prior.github_rest_accept
        OR replacement.github_archive_accept IS DISTINCT FROM prior.github_archive_accept
        OR replacement.repository_source_authentication IS DISTINCT FROM prior.repository_source_authentication
        OR replacement.repository_source_revision IS DISTINCT FROM prior.repository_source_revision
        OR replacement.repository_archive_format IS DISTINCT FROM prior.repository_archive_format
        OR replacement.webhook_max_body_bytes IS DISTINCT FROM prior.webhook_max_body_bytes
        OR replacement.webhook_accept_timeout_ms IS DISTINCT FROM prior.webhook_accept_timeout_ms
        OR replacement.push_webhook_max_commits IS DISTINCT FROM prior.push_webhook_max_commits
        OR replacement.path_filter_max_commits IS DISTINCT FROM prior.path_filter_max_commits
        OR replacement.path_filter_max_changed_files IS DISTINCT FROM prior.path_filter_max_changed_files
        OR replacement.archive_max_compressed_bytes IS DISTINCT FROM prior.archive_max_compressed_bytes
        OR replacement.archive_max_decompressed_bytes IS DISTINCT FROM prior.archive_max_decompressed_bytes
        OR replacement.archive_max_entries IS DISTINCT FROM prior.archive_max_entries
        OR replacement.archive_max_expanded_bytes IS DISTINCT FROM prior.archive_max_expanded_bytes
        OR replacement.archive_max_entry_path_bytes IS DISTINCT FROM prior.archive_max_entry_path_bytes
        OR replacement.archive_max_workflows IS DISTINCT FROM prior.archive_max_workflows
        OR replacement.workflow_max_bytes IS DISTINCT FROM prior.workflow_max_bytes;

    IF NOT (app_evidence_changed OR verifier_evidence_changed OR policy_evidence_changed)
        OR (CASE WHEN app_evidence_changed THEN
            prior.app_configuration_revision = 9223372036854775807
            OR replacement.app_configuration_revision <> prior.app_configuration_revision + 1
          ELSE replacement.app_configuration_revision <> prior.app_configuration_revision END)
        OR (CASE WHEN verifier_evidence_changed THEN
            prior.webhook_verifier_revision = 9223372036854775807
            OR replacement.webhook_verifier_revision <> prior.webhook_verifier_revision + 1
          ELSE replacement.webhook_verifier_revision <> prior.webhook_verifier_revision END)
        OR (CASE WHEN policy_evidence_changed THEN
            prior.policy_revision = 9223372036854775807
            OR replacement.policy_revision <> prior.policy_revision + 1
          ELSE replacement.policy_revision <> prior.policy_revision END)
        OR (CASE WHEN runtime_policy_changed THEN
            prior.runtime_policy_revision = 9223372036854775807
            OR replacement.runtime_policy_revision <> prior.runtime_policy_revision + 1
          ELSE replacement.runtime_policy_revision <> prior.runtime_policy_revision END)
    THEN
        RAISE EXCEPTION 'GitHub provider manifest policy revision did not advance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_revision_transition';
    END IF;
    RETURN NEW;
END;
$automata$;
