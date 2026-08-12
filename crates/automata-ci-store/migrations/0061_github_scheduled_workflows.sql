-- Immutable schedule discovery plus a current pointer and fenced fire ledger.
-- A registry revision binds one exact default-branch commit, repository archive,
-- canonical workflow inventory, and every validated schedule entry. Historical
-- revisions and terminal fires are retained as audit evidence.
--
-- The numeric owner is immutable provider evidence, not schedule-local state.
-- Existing revisions intentionally remain owner-unbound so their historical
-- manifest digests keep their original domains. Schedule rows must instead
-- reference an owner-bound revision exactly.
ALTER TABLE github_provider_manifest_revisions
    DROP CONSTRAINT github_provider_manifest_revisions_digest_canonical;

ALTER TABLE github_provider_manifest_revisions
    ADD COLUMN github_repository_owner_id BIGINT,
    ADD CONSTRAINT github_provider_manifest_revisions_owner_id_shape CHECK (
        github_repository_owner_id IS NULL OR github_repository_owner_id > 0
    ),
    ADD CONSTRAINT github_provider_manifest_revisions_owner_exact_unique UNIQUE (
        tenant_id, repository_id, provider_connection_id,
        manifest_revision, manifest_digest, github_repository_owner_id
    );

DO $automata$
DECLARE
    current_definition TEXT;
    owner_unbound_domain CONSTANT TEXT :=
        '        CASE' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''exact''' || chr(10) ||
        '             AND ($1).git_ref = ''refs/heads/main''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v3''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''all_direct''' || chr(10) ||
        '             AND ($1).git_ref = ''refs/heads/main''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v4.all-direct''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''exact''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v5.git-ref''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''all_direct''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v5.all-direct.git-ref''' || chr(10) ||
        '            ELSE ''invalid''' || chr(10) ||
        '        END,';
    owner_bound_domain CONSTANT TEXT :=
        '        CASE' || chr(10) ||
        '            WHEN ($1).github_repository_owner_id IS NOT NULL' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v6.owner-bound''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''exact''' || chr(10) ||
        '             AND ($1).git_ref = ''refs/heads/main''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v3''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''all_direct''' || chr(10) ||
        '             AND ($1).git_ref = ''refs/heads/main''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v4.all-direct''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''exact''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v5.git-ref''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''all_direct''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v5.all-direct.git-ref''' || chr(10) ||
        '            ELSE ''invalid''' || chr(10) ||
        '        END,';
    repository_id_part CONSTANT TEXT :=
        '    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(($1).github_repository_id))';
    owner_id_part CONSTANT TEXT :=
        '    || CASE WHEN ($1).github_repository_owner_id IS NULL' || chr(10) ||
        '        THEN ''''::BYTEA' || chr(10) ||
        '        ELSE automata_github_provider_manifest_digest_part(' || chr(10) ||
        '            pg_catalog.int8send(($1).github_repository_owner_id)' || chr(10) ||
        '        )' || chr(10) ||
        '       END';
BEGIN
    SELECT pg_get_functiondef(
        'automata_github_provider_manifest_digest(github_provider_manifest_revisions)'::REGPROCEDURE
    ) INTO current_definition;
    IF strpos(current_definition, owner_unbound_domain) = 0
        OR strpos(current_definition, repository_id_part) = 0
    THEN
        RAISE EXCEPTION 'unexpected GitHub provider manifest digest definition'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_provider_manifest_owner_digest_upgrade_exact';
    END IF;
    current_definition := replace(
        current_definition, owner_unbound_domain, owner_bound_domain
    );
    current_definition := replace(
        current_definition, repository_id_part, repository_id_part || chr(10) || owner_id_part
    );
    IF strpos(current_definition, owner_unbound_domain) > 0
        OR strpos(current_definition, owner_bound_domain) = 0
        OR strpos(current_definition, owner_id_part) = 0
    THEN
        RAISE EXCEPTION 'GitHub provider manifest owner digest upgrade was incomplete'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_provider_manifest_owner_digest_upgrade_exact';
    END IF;
    EXECUTE current_definition;
END;
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
        replacement.repository_visibility IS DISTINCT FROM prior.repository_visibility
        OR replacement.github_repository_owner_id IS DISTINCT FROM prior.github_repository_owner_id
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

CREATE TABLE github_schedule_discovery_claims (
    discovery_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    manifest_revision BIGINT NOT NULL,
    manifest_digest BYTEA NOT NULL,
    github_repository_owner_id BIGINT NOT NULL,
    source_authority_kind TEXT COLLATE "C" NOT NULL,
    private_source_authority_id UUID,
    private_source_authority_identity_digest BYTEA,
    private_source_authority_app_configuration_revision BIGINT,
    private_source_authority_policy_revision BIGINT,
    claim_owner_id UUID NOT NULL,
    claim_fence BIGINT NOT NULL,
    state TEXT COLLATE "C" NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    claim_expires_at_ms BIGINT NOT NULL,
    completed_registry_id UUID,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT github_schedule_discovery_claims_manifest
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        ) REFERENCES github_provider_manifest_revisions(
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_discovery_claims_manifest_owner
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest, github_repository_owner_id
        ) REFERENCES github_provider_manifest_revisions(
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest, github_repository_owner_id
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_discovery_claims_private_source_authority
        FOREIGN KEY (private_source_authority_id)
        REFERENCES github_server_service_authorities(id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_discovery_claims_non_nil CHECK (
        discovery_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND provider_connection_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT github_schedule_discovery_claims_shape CHECK (
        manifest_revision > 0
        AND octet_length(manifest_digest) = 32
        AND github_repository_owner_id > 0
        AND claim_fence > 0
        AND state IN ('claimed', 'completed', 'expired')
        AND claimed_at_ms >= 0
        AND claim_expires_at_ms > claimed_at_ms
        AND claim_expires_at_ms - claimed_at_ms <= 300000
        AND created_at_ms = claimed_at_ms
        AND updated_at_ms >= created_at_ms
        AND (
            state = 'claimed' AND completed_registry_id IS NULL
            OR state = 'completed' AND completed_registry_id IS NOT NULL
            OR state = 'expired' AND completed_registry_id IS NULL
        )
    ),
    CONSTRAINT github_schedule_discovery_claims_source_authority_shape CHECK (
        (
            source_authority_kind = 'public_anonymous'
            AND private_source_authority_id IS NULL
            AND private_source_authority_identity_digest IS NULL
            AND private_source_authority_app_configuration_revision IS NULL
            AND private_source_authority_policy_revision IS NULL
        ) OR (
            source_authority_kind = 'private_repository_source_read'
            AND private_source_authority_id IS NOT NULL
            AND private_source_authority_identity_digest IS NOT NULL
            AND octet_length(private_source_authority_identity_digest) = 32
            AND private_source_authority_app_configuration_revision > 0
            AND private_source_authority_policy_revision > 0
        )
    )
);

CREATE UNIQUE INDEX github_schedule_discovery_claims_one_live_repository
    ON github_schedule_discovery_claims(
        tenant_id, repository_id, provider_connection_id
    ) WHERE state = 'claimed';

CREATE FUNCTION automata_guard_github_schedule_discovery_claim_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    manifest github_provider_manifest_revisions%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    observed_at_ms BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    SELECT revision.* INTO manifest
      FROM github_provider_manifest_revisions AS revision
      JOIN github_provider_manifest_current AS current
        ON current.tenant_id = revision.tenant_id
       AND current.repository_id = revision.repository_id
       AND current.provider_connection_id = revision.provider_connection_id
       AND current.manifest_revision = revision.manifest_revision
       AND current.manifest_digest = revision.manifest_digest
     WHERE revision.tenant_id = NEW.tenant_id
       AND revision.repository_id = NEW.repository_id
       AND revision.provider_connection_id = NEW.provider_connection_id
       AND revision.manifest_revision = NEW.manifest_revision
       AND revision.manifest_digest = NEW.manifest_digest
     FOR SHARE OF revision, current;
    IF NEW.source_authority_kind = 'private_repository_source_read' THEN
        SELECT * INTO authority
          FROM github_server_service_authorities
         WHERE tenant_id = NEW.tenant_id
           AND id = NEW.private_source_authority_id
         FOR SHARE;
    END IF;
    IF manifest.provider_connection_id IS NULL
        OR manifest.github_repository_owner_id IS NULL
        OR manifest.github_repository_owner_id <> NEW.github_repository_owner_id
        OR NEW.claimed_at_ms > observed_at_ms
        OR observed_at_ms - NEW.claimed_at_ms > 60000
        OR NEW.claim_expires_at_ms <= observed_at_ms
        OR (
            NEW.source_authority_kind = 'public_anonymous'
            AND manifest.repository_visibility <> 'public'
        )
        OR (
            NEW.source_authority_kind = 'private_repository_source_read'
            AND (
                manifest.repository_visibility <> 'private'
                OR authority.id IS NULL
                OR authority.repository_id <> NEW.repository_id
                OR authority.provider_connection_id <> NEW.provider_connection_id
                OR authority.provider_installation_id <> manifest.provider_installation_id
                OR authority.github_app_id <> manifest.github_app_id
                OR authority.github_repository_id <> manifest.github_repository_id
                OR authority.github_repository_name <> manifest.github_repository_name
                OR authority.service_scope <> 'private_repository_source_read'
                OR authority.github_app_client_id <> manifest.github_app_client_id
                OR authority.github_app_jwt_issuer_kind <>
                    manifest.github_app_jwt_issuer_kind
                OR authority.app_key_spki_sha256 <> manifest.app_key_spki_sha256
                OR authority.app_configuration_revision <>
                    NEW.private_source_authority_app_configuration_revision
                OR authority.app_configuration_revision <> manifest.app_configuration_revision
                OR authority.policy_revision <> NEW.private_source_authority_policy_revision
                OR authority.policy_revision <> manifest.policy_revision
                OR authority.identity_digest <> NEW.private_source_authority_identity_digest
                OR authority.state <> 'active'
                OR authority.created_at_ms > NEW.claimed_at_ms
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub schedule discovery authority is not exact and live'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_discovery_authority_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_schedule_discovery_claims_00_insert_guard
BEFORE INSERT ON github_schedule_discovery_claims
FOR EACH ROW EXECUTE FUNCTION automata_guard_github_schedule_discovery_claim_insert();

CREATE FUNCTION automata_guard_github_schedule_discovery_claim_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    observed_at_ms BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    IF TG_OP = 'DELETE'
        OR OLD.state <> 'claimed'
        OR NEW.discovery_id IS DISTINCT FROM OLD.discovery_id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.manifest_revision IS DISTINCT FROM OLD.manifest_revision
        OR NEW.manifest_digest IS DISTINCT FROM OLD.manifest_digest
        OR NEW.github_repository_owner_id IS DISTINCT FROM OLD.github_repository_owner_id
        OR NEW.source_authority_kind IS DISTINCT FROM OLD.source_authority_kind
        OR NEW.private_source_authority_id IS DISTINCT FROM OLD.private_source_authority_id
        OR NEW.private_source_authority_identity_digest IS DISTINCT FROM
            OLD.private_source_authority_identity_digest
        OR NEW.private_source_authority_app_configuration_revision IS DISTINCT FROM
            OLD.private_source_authority_app_configuration_revision
        OR NEW.private_source_authority_policy_revision IS DISTINCT FROM
            OLD.private_source_authority_policy_revision
        OR NEW.claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
        OR NEW.claim_fence IS DISTINCT FROM OLD.claim_fence
        OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
        OR NEW.claim_expires_at_ms IS DISTINCT FROM OLD.claim_expires_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.state NOT IN ('completed', 'expired')
        OR NEW.state = 'completed' AND (
            NEW.updated_at_ms >= OLD.claim_expires_at_ms
            OR observed_at_ms >= OLD.claim_expires_at_ms
        )
        OR NEW.state = 'expired' AND (
            NEW.updated_at_ms < OLD.claim_expires_at_ms
            OR observed_at_ms < OLD.claim_expires_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub schedule discovery transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_discovery_transition_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_schedule_discovery_claims_transition_exact
BEFORE UPDATE OR DELETE ON github_schedule_discovery_claims
FOR EACH ROW EXECUTE FUNCTION automata_guard_github_schedule_discovery_claim_transition();

ALTER TABLE github_server_service_authority_handoffs
    DROP CONSTRAINT github_server_service_handoffs_action,
    ADD CONSTRAINT github_server_service_handoffs_action CHECK (
        consumer_action IN (
            'ensure_check_suite', 'create_check_run', 'reconcile_check_run',
            'publish_check_run', 'fetch_private_repository_revision',
            'fetch_private_repository_changed_files',
            'discover_private_repository_schedules'
        )
    );

CREATE OR REPLACE FUNCTION automata_github_server_service_handoff_insert_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    issuance github_server_service_authority_issuances%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    check_outbox github_check_projection_outbox%ROWTYPE;
    check_subject github_check_subjects%ROWTYPE;
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    discovery_exact BOOLEAN;
    observed_at_ms BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    SELECT * INTO issuance
    FROM github_server_service_authority_issuances
    WHERE tenant_id = NEW.tenant_id
      AND authority_id = NEW.authority_id
      AND generation = NEW.generation
    FOR SHARE;
    SELECT * INTO authority
    FROM github_server_service_authorities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.authority_id
    FOR SHARE;
    IF issuance.authority_id IS NULL
        OR authority.id IS NULL
        OR authority.state <> 'active'
        OR authority.current_issuance_generation IS DISTINCT FROM NEW.generation
        OR issuance.state <> 'ready'
        OR issuance.state_updated_at_ms > NEW.granted_at_ms
        OR authority.state_updated_at_ms > NEW.granted_at_ms
        OR NEW.required_through_ms
            > issuance.provider_expires_at_ms - 60000
    THEN
        RAISE EXCEPTION 'GitHub server-service handoff authority is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_handoffs_authority_exact';
    END IF;

    IF authority.service_scope = 'checks_write' THEN
        SELECT * INTO check_outbox
        FROM github_check_projection_outbox
        WHERE subject_id = NEW.consumer_id
        FOR SHARE;
        SELECT * INTO check_subject
        FROM github_check_subjects
        WHERE id = NEW.consumer_id
        FOR SHARE;
        IF check_outbox.subject_id IS NULL
            OR check_subject.id IS NULL
            OR check_outbox.state <> 'claimed'
            OR check_outbox.claim_owner_id <> NEW.consumer_owner_id
            OR check_outbox.claim_fence <> NEW.consumer_claim_fence
            OR check_outbox.claimed_desired_revision <> NEW.consumer_revision
            OR check_outbox.claimed_at_ms IS NULL
            OR check_outbox.claim_expires_at_ms IS NULL
            OR check_outbox.claimed_at_ms > NEW.granted_at_ms
            OR check_outbox.state_updated_at_ms > NEW.granted_at_ms
            OR check_outbox.claim_expires_at_ms <= NEW.granted_at_ms
            OR NEW.required_through_ms::NUMERIC
                > check_outbox.claim_expires_at_ms::NUMERIC
                    + (CASE NEW.consumer_action
                        WHEN 'publish_check_run' THEN 600000
                        ELSE 300000
                    END)
            OR (CASE NEW.consumer_action
                WHEN 'ensure_check_suite' THEN check_outbox.claim_action <> 'ensure_suite'
                WHEN 'create_check_run' THEN check_outbox.claim_action <> 'prepare_run_create'
                WHEN 'reconcile_check_run' THEN check_outbox.claim_action <> 'reconcile_run_create'
                WHEN 'publish_check_run' THEN check_outbox.claim_action <> 'publish'
                ELSE TRUE
            END)
            OR check_subject.tenant_id <> authority.tenant_id
            OR check_subject.repository_id <> authority.repository_id
            OR check_subject.provider_connection_id <> authority.provider_connection_id
            OR check_subject.provider_installation_id <> authority.provider_installation_id
            OR check_subject.github_app_id <> authority.github_app_id
            OR check_subject.github_repository_id <> authority.github_repository_id
            OR check_subject.github_repository_name <> authority.github_repository_name
        THEN
            RAISE EXCEPTION 'GitHub Checks handoff consumer claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_handoffs_checks_claim_exact';
        END IF;
    ELSIF authority.service_scope = 'private_repository_source_read' THEN
        IF NEW.consumer_action = 'discover_private_repository_schedules' THEN
            SELECT EXISTS (
                SELECT 1
                  FROM github_schedule_discovery_claims AS discovery
                  JOIN github_provider_manifest_current AS current
                    ON current.tenant_id = discovery.tenant_id
                   AND current.repository_id = discovery.repository_id
                   AND current.provider_connection_id = discovery.provider_connection_id
                   AND current.manifest_revision = discovery.manifest_revision
                   AND current.manifest_digest = discovery.manifest_digest
                  JOIN github_provider_manifest_revisions AS manifest
                    ON manifest.tenant_id = current.tenant_id
                   AND manifest.repository_id = current.repository_id
                   AND manifest.provider_connection_id = current.provider_connection_id
                   AND manifest.manifest_revision = current.manifest_revision
                   AND manifest.manifest_digest = current.manifest_digest
                  JOIN repositories AS schedule_repository
                    ON schedule_repository.id = discovery.repository_id
                   AND schedule_repository.tenant_id = discovery.tenant_id
                   AND schedule_repository.scm_provider = 'github'
                   AND schedule_repository.provider_repository_id =
                       manifest.github_repository_id::TEXT
                 WHERE discovery.discovery_id = NEW.consumer_id
                   AND discovery.state = 'claimed'
                   AND discovery.claim_owner_id = NEW.consumer_owner_id
                   AND discovery.claim_fence = NEW.consumer_claim_fence
                   AND NEW.consumer_revision = 1
                   AND discovery.claimed_at_ms <= NEW.granted_at_ms
                   AND discovery.updated_at_ms <= NEW.granted_at_ms
                   AND discovery.claim_expires_at_ms > NEW.granted_at_ms
                   AND discovery.claim_expires_at_ms > observed_at_ms
                   AND NEW.required_through_ms::NUMERIC <=
                       discovery.claim_expires_at_ms::NUMERIC + 300000
                   AND discovery.tenant_id = authority.tenant_id
                   AND discovery.repository_id = authority.repository_id
                   AND discovery.provider_connection_id = authority.provider_connection_id
                   AND discovery.source_authority_kind =
                       'private_repository_source_read'
                   AND discovery.private_source_authority_id = authority.id
                   AND discovery.private_source_authority_identity_digest =
                       authority.identity_digest
                   AND discovery.private_source_authority_app_configuration_revision =
                       authority.app_configuration_revision
                   AND discovery.private_source_authority_policy_revision =
                       authority.policy_revision
                   AND manifest.provider_installation_id =
                       authority.provider_installation_id
                   AND manifest.github_app_id = authority.github_app_id
                   AND manifest.github_repository_id = authority.github_repository_id
                   AND manifest.github_repository_name = authority.github_repository_name
                   AND manifest.github_repository_owner_id IS NOT NULL
                   AND manifest.github_repository_owner_id =
                       discovery.github_repository_owner_id
                 FOR SHARE OF discovery, current, manifest, schedule_repository
            ) INTO discovery_exact;
            IF discovery_exact IS DISTINCT FROM TRUE THEN
                RAISE EXCEPTION 'private GitHub schedule discovery handoff claim is not exact'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT =
                              'github_server_service_handoffs_schedule_discovery_claim_exact';
            END IF;
        ELSE
            SELECT * INTO delivery
            FROM provider_delivery_inbox
            WHERE id = NEW.consumer_id
            FOR SHARE;
            SELECT * INTO repository
            FROM repositories
            WHERE id = authority.repository_id
              AND tenant_id = authority.tenant_id
            FOR SHARE;
            IF delivery.id IS NULL
                OR repository.id IS NULL
                OR delivery.state IS DISTINCT FROM 'claimed'
                OR delivery.claim_owner_id IS DISTINCT FROM NEW.consumer_owner_id
                OR delivery.claim_fence IS DISTINCT FROM NEW.consumer_claim_fence
                OR delivery.attempt_count IS DISTINCT FROM NEW.consumer_revision
                OR delivery.claimed_at_ms IS NULL
                OR delivery.claim_expires_at_ms IS NULL
                OR delivery.claimed_at_ms > NEW.granted_at_ms
                OR delivery.state_updated_at_ms > NEW.granted_at_ms
                OR delivery.claim_expires_at_ms <= NEW.granted_at_ms
                OR NEW.required_through_ms::NUMERIC
                    > delivery.claim_expires_at_ms::NUMERIC + 300000
                OR NEW.consumer_action NOT IN (
                    'fetch_private_repository_revision',
                    'fetch_private_repository_changed_files'
                )
                OR delivery.tenant_id IS DISTINCT FROM authority.tenant_id
                OR delivery.provider IS DISTINCT FROM 'github'
                OR delivery.repository_visibility IS DISTINCT FROM 'private'
                OR delivery.connection_id IS DISTINCT FROM authority.provider_connection_id
                OR delivery.installation_id IS DISTINCT FROM authority.provider_installation_id
                OR delivery.provider_repository_id IS DISTINCT FROM authority.github_repository_id
                OR delivery.repository_identity IS DISTINCT FROM authority.github_repository_name
                OR repository.scm_provider IS DISTINCT FROM 'github'
                OR repository.provider_repository_id
                    IS DISTINCT FROM authority.github_repository_id::TEXT
                OR repository.owner || '/' || repository.name
                    IS DISTINCT FROM authority.github_repository_name
            THEN
                RAISE EXCEPTION 'private GitHub source handoff consumer claim is not exact'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_handoffs_source_claim_exact';
            END IF;
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub server-service handoff scope is unknown'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_handoffs_scope_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TABLE github_schedule_registry_revisions (
    registry_id UUID PRIMARY KEY,
    discovery_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    manifest_revision BIGINT NOT NULL,
    manifest_digest BYTEA NOT NULL,
    github_repository_owner_id BIGINT NOT NULL,
    default_branch_ref TEXT COLLATE "C" NOT NULL,
    source_revision TEXT COLLATE "C" NOT NULL,
    source_authority_kind TEXT COLLATE "C" NOT NULL,
    private_source_authority_id UUID,
    private_source_authority_identity_digest BYTEA,
    private_source_authority_app_configuration_revision BIGINT,
    private_source_authority_policy_revision BIGINT,
    archive_digest BYTEA NOT NULL,
    archive_object_key TEXT COLLATE "C" NOT NULL,
    archive_size_bytes BIGINT NOT NULL,
    archive_media_type TEXT COLLATE "C" NOT NULL,
    inventory_digest BYTEA NOT NULL,
    schedule_count SMALLINT NOT NULL,
    discovered_at_ms BIGINT NOT NULL,
    CONSTRAINT github_schedule_registry_revisions_identity_unique UNIQUE (
        tenant_id, repository_id, provider_connection_id, registry_id
    ),
    CONSTRAINT github_schedule_registry_revisions_discovery_unique UNIQUE (discovery_id),
    CONSTRAINT github_schedule_registry_revisions_discovery
        FOREIGN KEY (discovery_id)
        REFERENCES github_schedule_discovery_claims(discovery_id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_registry_revisions_exact_unique UNIQUE (
        tenant_id, repository_id, provider_connection_id, registry_id,
        manifest_revision, manifest_digest, default_branch_ref, source_revision,
        github_repository_owner_id
    ),
    CONSTRAINT github_schedule_registry_revisions_replay_unique UNIQUE (
        tenant_id, repository_id, provider_connection_id,
        manifest_revision, source_revision, inventory_digest
    ),
    CONSTRAINT github_schedule_registry_revisions_manifest
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        )
        REFERENCES github_provider_manifest_revisions (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_registry_revisions_manifest_owner
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest, github_repository_owner_id
        ) REFERENCES github_provider_manifest_revisions (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest, github_repository_owner_id
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_registry_revisions_private_source_authority
        FOREIGN KEY (private_source_authority_id)
        REFERENCES github_server_service_authorities(id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_registry_revisions_non_nil CHECK (
        registry_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND discovery_id = registry_id
    ),
    CONSTRAINT github_schedule_registry_revisions_digest_shape CHECK (
        octet_length(manifest_digest) = 32
        AND octet_length(archive_digest) = 32
        AND octet_length(inventory_digest) = 32
        AND (
            private_source_authority_identity_digest IS NULL
            OR octet_length(private_source_authority_identity_digest) = 32
        )
    ),
    CONSTRAINT github_schedule_registry_revisions_source_authority_shape CHECK (
        (
            source_authority_kind = 'public_anonymous'
            AND private_source_authority_id IS NULL
            AND private_source_authority_identity_digest IS NULL
            AND private_source_authority_app_configuration_revision IS NULL
            AND private_source_authority_policy_revision IS NULL
        ) OR (
            source_authority_kind = 'private_repository_source_read'
            AND private_source_authority_id IS NOT NULL
            AND private_source_authority_id <>
                '00000000-0000-0000-0000-000000000000'::UUID
            AND private_source_authority_identity_digest IS NOT NULL
            AND private_source_authority_app_configuration_revision > 0
            AND private_source_authority_policy_revision > 0
        )
    ),
    CONSTRAINT github_schedule_registry_revisions_source_shape CHECK (
        default_branch_ref ~ '^refs/heads/[^[:cntrl:][:space:]]+$'
        AND octet_length(default_branch_ref) BETWEEN 12 AND 1024
        AND source_revision ~ '^[0-9a-f]{40}$'
    ),
    CONSTRAINT github_schedule_registry_revisions_archive_shape CHECK (
        octet_length(archive_object_key) BETWEEN 1 AND 1024
        AND archive_object_key = btrim(archive_object_key)
        AND archive_object_key !~ '[[:cntrl:]]'
        AND archive_size_bytes BETWEEN 1 AND 268435456
        AND archive_media_type = 'application/vnd.automata.github-repository-archive+gzip'
    ),
    CONSTRAINT github_schedule_registry_revisions_bounds CHECK (
        manifest_revision > 0
        AND github_repository_owner_id > 0
        AND schedule_count BETWEEN 0 AND 256
        AND discovered_at_ms >= 0
    )
);

ALTER TABLE github_schedule_discovery_claims
    ADD CONSTRAINT github_schedule_discovery_claims_completed_registry
    FOREIGN KEY (completed_registry_id)
    REFERENCES github_schedule_registry_revisions(registry_id) ON DELETE RESTRICT;

CREATE FUNCTION automata_guard_github_schedule_registry_revision_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    manifest github_provider_manifest_revisions%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    discovery github_schedule_discovery_claims%ROWTYPE;
    observed_at_ms BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    SELECT * INTO discovery
      FROM github_schedule_discovery_claims
     WHERE discovery_id = NEW.discovery_id
     FOR UPDATE;
    IF discovery.discovery_id IS NULL
        OR discovery.state <> 'claimed'
        OR discovery.claimed_at_ms > NEW.discovered_at_ms
        OR NEW.discovered_at_ms >= discovery.claim_expires_at_ms
        OR observed_at_ms >= discovery.claim_expires_at_ms
        OR discovery.tenant_id <> NEW.tenant_id
        OR discovery.repository_id <> NEW.repository_id
        OR discovery.provider_connection_id <> NEW.provider_connection_id
        OR discovery.manifest_revision <> NEW.manifest_revision
        OR discovery.manifest_digest <> NEW.manifest_digest
        OR discovery.github_repository_owner_id <> NEW.github_repository_owner_id
        OR discovery.source_authority_kind <> NEW.source_authority_kind
        OR discovery.private_source_authority_id IS DISTINCT FROM
            NEW.private_source_authority_id
        OR discovery.private_source_authority_identity_digest IS DISTINCT FROM
            NEW.private_source_authority_identity_digest
        OR discovery.private_source_authority_app_configuration_revision IS DISTINCT FROM
            NEW.private_source_authority_app_configuration_revision
        OR discovery.private_source_authority_policy_revision IS DISTINCT FROM
            NEW.private_source_authority_policy_revision
    THEN
        RAISE EXCEPTION 'GitHub schedule registry lacks an exact live discovery claim'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_discovery_claim_exact';
    END IF;
    SELECT revision.* INTO manifest
      FROM github_provider_manifest_revisions AS revision
      JOIN github_provider_manifest_current AS current
        ON current.tenant_id = revision.tenant_id
       AND current.repository_id = revision.repository_id
       AND current.provider_connection_id = revision.provider_connection_id
       AND current.manifest_revision = revision.manifest_revision
       AND current.manifest_digest = revision.manifest_digest
     WHERE revision.tenant_id = NEW.tenant_id
       AND revision.repository_id = NEW.repository_id
       AND revision.provider_connection_id = NEW.provider_connection_id
       AND revision.manifest_revision = NEW.manifest_revision
       AND revision.manifest_digest = NEW.manifest_digest
     FOR SHARE OF revision, current;
    IF manifest.provider_connection_id IS NULL
        OR manifest.github_repository_owner_id IS NULL
        OR manifest.github_repository_owner_id <> NEW.github_repository_owner_id
        OR manifest.git_ref <> NEW.default_branch_ref
    THEN
        RAISE EXCEPTION 'GitHub schedule registry lacks its exact current manifest'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_source_authority_exact';
    END IF;

    IF NEW.source_authority_kind = 'private_repository_source_read' THEN
        SELECT * INTO authority
          FROM github_server_service_authorities
         WHERE tenant_id = NEW.tenant_id
           AND id = NEW.private_source_authority_id
         FOR SHARE;
    END IF;
    IF (
        NEW.source_authority_kind = 'public_anonymous'
        AND manifest.repository_visibility <> 'public'
    ) OR (
        NEW.source_authority_kind = 'private_repository_source_read'
        AND (
            manifest.repository_visibility <> 'private'
            OR authority.id IS NULL
            OR authority.repository_id <> NEW.repository_id
            OR authority.provider_connection_id <> NEW.provider_connection_id
            OR authority.provider_installation_id <> manifest.provider_installation_id
            OR authority.github_app_id <> manifest.github_app_id
            OR authority.github_repository_id <> manifest.github_repository_id
            OR authority.github_repository_name <> manifest.github_repository_name
            OR authority.service_scope <> 'private_repository_source_read'
            OR authority.github_app_client_id <> manifest.github_app_client_id
            OR authority.github_app_jwt_issuer_kind <>
                manifest.github_app_jwt_issuer_kind
            OR authority.app_key_spki_sha256 <> manifest.app_key_spki_sha256
            OR authority.app_configuration_revision <>
                NEW.private_source_authority_app_configuration_revision
            OR authority.app_configuration_revision <> manifest.app_configuration_revision
            OR authority.policy_revision <> NEW.private_source_authority_policy_revision
            OR authority.policy_revision <> manifest.policy_revision
            OR authority.identity_digest <> NEW.private_source_authority_identity_digest
            OR authority.state <> 'active'
            OR authority.created_at_ms > NEW.discovered_at_ms
        )
    ) THEN
        RAISE EXCEPTION 'GitHub schedule registry source authority is not exact and live'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_source_authority_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_schedule_registry_revisions_00_insert_guard
BEFORE INSERT ON github_schedule_registry_revisions
FOR EACH ROW EXECUTE FUNCTION automata_guard_github_schedule_registry_revision_insert();

CREATE TABLE github_schedule_registry_entries (
    registry_id UUID NOT NULL,
    ordinal SMALLINT NOT NULL,
    workflow_path TEXT COLLATE "C" NOT NULL,
    workflow_source_digest BYTEA NOT NULL,
    schedule_ordinal SMALLINT NOT NULL,
    cron_expression TEXT COLLATE "C" NOT NULL,
    timezone TEXT COLLATE "C" NOT NULL,
    entry_digest BYTEA NOT NULL,
    CONSTRAINT github_schedule_registry_entries_primary_key
        PRIMARY KEY (registry_id, ordinal),
    CONSTRAINT github_schedule_registry_entries_source_identity_unique
        UNIQUE (registry_id, workflow_path, schedule_ordinal),
    CONSTRAINT github_schedule_registry_entries_digest_unique
        UNIQUE (registry_id, entry_digest),
    CONSTRAINT github_schedule_registry_entries_registry
        FOREIGN KEY (registry_id)
        REFERENCES github_schedule_registry_revisions(registry_id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_registry_entries_shape CHECK (
        ordinal BETWEEN 0 AND 255
        AND schedule_ordinal BETWEEN 0 AND 63
        AND workflow_path ~ '^\.github/workflows/[^/]+\.ya?ml$'
        AND workflow_path !~ '[[:cntrl:]\\]'
        AND octet_length(workflow_source_digest) = 32
        AND octet_length(entry_digest) = 32
        AND octet_length(cron_expression) BETWEEN 1 AND 256
        AND cron_expression ~ '^[A-Za-z0-9*,/ -]+$'
        AND array_length(regexp_split_to_array(btrim(cron_expression), '[[:space:]]+'), 1) = 5
        AND octet_length(timezone) BETWEEN 1 AND 255
        AND timezone = btrim(timezone)
        AND timezone !~ '[[:cntrl:]]'
    )
);

CREATE TABLE github_schedule_registry_seals (
    registry_id UUID PRIMARY KEY,
    inventory_digest BYTEA NOT NULL,
    schedule_count SMALLINT NOT NULL,
    sealed_at_ms BIGINT NOT NULL,
    CONSTRAINT github_schedule_registry_seals_revision
        FOREIGN KEY (registry_id)
        REFERENCES github_schedule_registry_revisions(registry_id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_registry_seals_shape CHECK (
        octet_length(inventory_digest) = 32
        AND schedule_count BETWEEN 0 AND 256
        AND sealed_at_ms >= 0
    )
);

CREATE FUNCTION automata_seal_github_schedule_registry()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    revision_count SMALLINT;
    revision_digest BYTEA;
    actual_count BIGINT;
    minimum_ordinal SMALLINT;
    maximum_ordinal SMALLINT;
BEGIN
    SELECT schedule_count, inventory_digest
      INTO revision_count, revision_digest
     FROM github_schedule_registry_revisions
     WHERE registry_id = NEW.registry_id
     FOR UPDATE;
    SELECT count(*), min(ordinal), max(ordinal)
      INTO actual_count, minimum_ordinal, maximum_ordinal
      FROM github_schedule_registry_entries
     WHERE registry_id = NEW.registry_id;
    IF revision_count IS NULL
        OR revision_count <> NEW.schedule_count
        OR revision_digest <> NEW.inventory_digest
        OR actual_count <> NEW.schedule_count
        OR (
            NEW.schedule_count > 0
            AND (minimum_ordinal <> 0 OR maximum_ordinal <> NEW.schedule_count - 1)
        )
    THEN
        RAISE EXCEPTION 'GitHub schedule registry seal does not match exact entries'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_seal_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_schedule_registry_seals_exact
BEFORE INSERT ON github_schedule_registry_seals
FOR EACH ROW EXECUTE FUNCTION automata_seal_github_schedule_registry();

CREATE FUNCTION automata_guard_github_schedule_registry_entry_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
      FROM github_schedule_registry_revisions
     WHERE registry_id = NEW.registry_id
     FOR KEY SHARE;
    IF EXISTS (
        SELECT 1 FROM github_schedule_registry_seals
        WHERE registry_id = NEW.registry_id
    ) THEN
        RAISE EXCEPTION 'sealed GitHub schedule registry cannot accept entries'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_entry_after_seal';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_schedule_registry_entries_00_require_unsealed
BEFORE INSERT ON github_schedule_registry_entries
FOR EACH ROW EXECUTE FUNCTION automata_guard_github_schedule_registry_entry_insert();

CREATE TABLE github_schedule_registry_current (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    registry_id UUID NOT NULL,
    activated_at_ms BIGINT NOT NULL,
    CONSTRAINT github_schedule_registry_current_primary_key
        PRIMARY KEY (tenant_id, repository_id, provider_connection_id),
    CONSTRAINT github_schedule_registry_current_registry_unique
        UNIQUE (tenant_id, repository_id, provider_connection_id, registry_id),
    CONSTRAINT github_schedule_registry_current_revision
        FOREIGN KEY (tenant_id, repository_id, provider_connection_id, registry_id)
        REFERENCES github_schedule_registry_revisions(
            tenant_id, repository_id, provider_connection_id, registry_id
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_registry_current_seal
        FOREIGN KEY (registry_id)
        REFERENCES github_schedule_registry_seals(registry_id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_registry_current_time CHECK (activated_at_ms >= 0)
);

CREATE TABLE github_schedule_runtime (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    registry_id UUID NOT NULL,
    entry_ordinal SMALLINT NOT NULL,
    next_fire_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT github_schedule_runtime_primary_key
        PRIMARY KEY (
            tenant_id, repository_id, provider_connection_id, entry_ordinal
        ),
    CONSTRAINT github_schedule_runtime_current
        FOREIGN KEY (tenant_id, repository_id, provider_connection_id, registry_id)
        REFERENCES github_schedule_registry_current(
            tenant_id, repository_id, provider_connection_id, registry_id
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_runtime_entry
        FOREIGN KEY (registry_id, entry_ordinal)
        REFERENCES github_schedule_registry_entries(registry_id, ordinal) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_runtime_time CHECK (
        next_fire_at_ms >= 0 AND updated_at_ms >= 0
    )
);

CREATE INDEX github_schedule_runtime_due
    ON github_schedule_runtime(
        next_fire_at_ms, tenant_id, repository_id,
        provider_connection_id, entry_ordinal
    );

CREATE TABLE github_schedule_fires (
    fire_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    registry_id UUID NOT NULL,
    entry_ordinal SMALLINT NOT NULL,
    scheduled_at_ms BIGINT NOT NULL,
    state TEXT COLLATE "C" NOT NULL DEFAULT 'pending',
    attempt_count SMALLINT NOT NULL DEFAULT 0,
    claim_fence BIGINT NOT NULL DEFAULT 0,
    claim_owner_id UUID,
    claimed_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    next_attempt_at_ms BIGINT NOT NULL,
    workflow_run_id UUID,
    failure_kind TEXT COLLATE "C",
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT github_schedule_fires_entry_time_unique
        UNIQUE (registry_id, entry_ordinal, scheduled_at_ms),
    CONSTRAINT github_schedule_fires_exact_identity_unique UNIQUE (
        tenant_id, repository_id, provider_connection_id, fire_id,
        registry_id, entry_ordinal, scheduled_at_ms
    ),
    CONSTRAINT github_schedule_fires_subject_identity_unique UNIQUE (
        tenant_id, repository_id, provider_connection_id, fire_id
    ),
    CONSTRAINT github_schedule_fires_run_identity_unique UNIQUE (
        tenant_id, repository_id, fire_id
    ),
    CONSTRAINT github_schedule_fires_entry
        FOREIGN KEY (registry_id, entry_ordinal)
        REFERENCES github_schedule_registry_entries(registry_id, ordinal) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_fires_registry_identity
        FOREIGN KEY (tenant_id, repository_id, provider_connection_id, registry_id)
        REFERENCES github_schedule_registry_revisions(
            tenant_id, repository_id, provider_connection_id, registry_id
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_fires_repository_run
        FOREIGN KEY (repository_id, workflow_run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_fires_non_nil CHECK (
        fire_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND (claim_owner_id IS NULL OR claim_owner_id <>
            '00000000-0000-0000-0000-000000000000'::UUID)
    ),
    CONSTRAINT github_schedule_fires_bounds CHECK (
        entry_ordinal BETWEEN 0 AND 255
        AND scheduled_at_ms >= 0
        AND attempt_count BETWEEN 0 AND 20
        AND claim_fence >= 0
        AND next_attempt_at_ms >= scheduled_at_ms
        AND created_at_ms >= 0
        AND updated_at_ms >= created_at_ms
    ),
    CONSTRAINT github_schedule_fires_state_shape CHECK (
        state = 'pending'
            AND claim_owner_id IS NULL
            AND claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND workflow_run_id IS NULL
            AND failure_kind IS NULL
        OR state = 'claimed'
            AND attempt_count > 0
            AND claim_fence > 0
            AND claim_owner_id IS NOT NULL
            AND claimed_at_ms IS NOT NULL
            AND claim_expires_at_ms > claimed_at_ms
            AND workflow_run_id IS NULL
            AND failure_kind IS NULL
        OR state = 'admitted'
            AND claim_owner_id IS NULL
            AND claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND workflow_run_id IS NOT NULL
            AND failure_kind IS NULL
        OR state IN ('skipped', 'failed')
            AND claim_owner_id IS NULL
            AND claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND workflow_run_id IS NULL
            AND octet_length(failure_kind) BETWEEN 1 AND 128
            AND failure_kind ~ '^[a-z0-9](?:[a-z0-9_.:-]*[a-z0-9])?$|^[a-z0-9]$'
    )
);

CREATE INDEX github_schedule_fires_claimable
    ON github_schedule_fires(next_attempt_at_ms, scheduled_at_ms, fire_id)
    WHERE state IN ('pending', 'claimed');

CREATE TABLE github_schedule_fire_attempts (
    fire_id UUID NOT NULL,
    attempt SMALLINT NOT NULL,
    claim_fence BIGINT NOT NULL,
    claim_owner_id UUID NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    claim_expires_at_ms BIGINT NOT NULL,
    concluded_at_ms BIGINT NOT NULL,
    outcome TEXT COLLATE "C" NOT NULL,
    failure_kind TEXT COLLATE "C",
    CONSTRAINT github_schedule_fire_attempts_primary_key PRIMARY KEY (fire_id, attempt),
    CONSTRAINT github_schedule_fire_attempts_fence_unique UNIQUE (fire_id, claim_fence),
    CONSTRAINT github_schedule_fire_attempts_fire
        FOREIGN KEY (fire_id) REFERENCES github_schedule_fires(fire_id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_fire_attempts_shape CHECK (
        attempt BETWEEN 1 AND 20
        AND claim_fence > 0
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND claimed_at_ms >= 0
        AND claim_expires_at_ms > claimed_at_ms
        AND concluded_at_ms >= claimed_at_ms
        AND (
            outcome = 'admitted' AND failure_kind IS NULL
            OR outcome IN ('retry', 'expired', 'skipped', 'failed')
                AND octet_length(failure_kind) BETWEEN 1 AND 128
                AND failure_kind ~ '^[a-z0-9](?:[a-z0-9_.:-]*[a-z0-9])?$|^[a-z0-9]$'
        )
    )
);

-- A Check has exactly one closed origin. Existing webhook subjects retain
-- their delivery identity; scheduled subjects bind one exact durable fire.
LOCK TABLE github_check_subjects IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE github_check_subjects
    ALTER COLUMN provider_delivery_id DROP NOT NULL,
    ADD COLUMN origin_kind TEXT COLLATE "C" NOT NULL DEFAULT 'provider_delivery',
    ADD COLUMN schedule_fire_id UUID,
    ADD CONSTRAINT github_check_subjects_origin_exact CHECK (
        num_nonnulls(provider_delivery_id, schedule_fire_id) = 1
        AND (
            origin_kind = 'provider_delivery'
            AND provider_delivery_id IS NOT NULL
            AND schedule_fire_id IS NULL
            OR origin_kind = 'scheduled_fire'
            AND provider_delivery_id IS NULL
            AND schedule_fire_id IS NOT NULL
        )
    ),
    ADD CONSTRAINT github_check_subjects_schedule_fire_non_nil CHECK (
        schedule_fire_id IS NULL
        OR schedule_fire_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    ADD CONSTRAINT github_check_subjects_schedule_fire_key_unique
        UNIQUE (schedule_fire_id, subject_key),
    ADD CONSTRAINT github_check_subjects_schedule_identity_unique
        UNIQUE (
            tenant_id, repository_id, provider_connection_id,
            schedule_fire_id, id
        ),
    ADD CONSTRAINT github_check_subjects_schedule_fire
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id, schedule_fire_id
        ) REFERENCES github_schedule_fires(
            tenant_id, repository_id, provider_connection_id, fire_id
        ) ON DELETE RESTRICT;

CREATE FUNCTION automata_github_check_subject_origin_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.origin_kind IS DISTINCT FROM OLD.origin_kind
        OR NEW.provider_delivery_id IS DISTINCT FROM OLD.provider_delivery_id
        OR NEW.schedule_fire_id IS DISTINCT FROM OLD.schedule_fire_id
    THEN
        RAISE EXCEPTION 'GitHub Check subject origin is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_check_subjects_00_origin_immutable
BEFORE UPDATE ON github_check_subjects
FOR EACH ROW EXECUTE FUNCTION automata_github_check_subject_origin_immutable();

-- The original canonical-name trigger remains the sole derivation point, but
-- uses a typed source rather than treating a scheduled fire as a delivery.
CREATE OR REPLACE FUNCTION automata_github_check_subject_canonical_name()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    schedule_name TEXT;
BEGIN
    SELECT * INTO repository
    FROM repositories
    WHERE id = NEW.repository_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;

    IF NEW.origin_kind = 'provider_delivery' THEN
        SELECT * INTO delivery
        FROM provider_delivery_inbox
        WHERE id = NEW.provider_delivery_id
          AND tenant_id = NEW.tenant_id
        FOR SHARE;
        IF delivery.id IS NULL
            OR repository.id IS NULL
            OR delivery.provider <> 'github'
            OR delivery.provider_repository_id <> NEW.github_repository_id
            OR delivery.repository_identity <> repository.owner || '/' || repository.name
        THEN
            RAISE EXCEPTION 'GitHub Check canonical repository identity is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_canonical_name_exact';
        END IF;
        NEW.github_repository_name := delivery.repository_identity;
    ELSIF NEW.origin_kind = 'scheduled_fire' THEN
        SELECT manifest.github_repository_name INTO schedule_name
        FROM github_schedule_fires AS fire
        JOIN github_schedule_registry_revisions AS registry
          ON registry.tenant_id = fire.tenant_id
         AND registry.repository_id = fire.repository_id
         AND registry.provider_connection_id = fire.provider_connection_id
         AND registry.registry_id = fire.registry_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = registry.tenant_id
         AND manifest.repository_id = registry.repository_id
         AND manifest.provider_connection_id = registry.provider_connection_id
         AND manifest.manifest_revision = registry.manifest_revision
         AND manifest.manifest_digest = registry.manifest_digest
        JOIN github_provider_manifest_current AS manifest_current
          ON manifest_current.tenant_id = manifest.tenant_id
         AND manifest_current.repository_id = manifest.repository_id
         AND manifest_current.provider_connection_id = manifest.provider_connection_id
         AND manifest_current.manifest_revision = manifest.manifest_revision
         AND manifest_current.manifest_digest = manifest.manifest_digest
        WHERE fire.fire_id = NEW.schedule_fire_id
          AND fire.tenant_id = NEW.tenant_id
          AND fire.repository_id = NEW.repository_id
          AND fire.provider_connection_id = NEW.provider_connection_id
        FOR SHARE OF fire, registry, manifest, manifest_current;
        IF schedule_name IS NULL
            OR repository.id IS NULL
            OR repository.scm_provider <> 'github'
            OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
            OR schedule_name <> repository.owner || '/' || repository.name
        THEN
            RAISE EXCEPTION 'GitHub Check canonical repository identity is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_canonical_name_exact';
        END IF;
        NEW.github_repository_name := schedule_name;
    ELSE
        RAISE EXCEPTION 'GitHub Check subject origin is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Delivery-specific signed evidence remains mandatory only for delivery
-- origins. Scheduled evidence is checked by its own typed trigger below.
CREATE OR REPLACE FUNCTION automata_github_check_subject_delivery_evidence_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    authority RECORD;
    workflow_authorized BOOLEAN := FALSE;
BEGIN
    IF NEW.origin_kind = 'scheduled_fire' THEN
        RETURN NEW;
    END IF;
    SELECT evidence_source.repository_id,
           evidence_source.provider_connection_id,
           evidence_source.provider_installation_id,
           evidence_source.github_repository_id,
           evidence_source.github_repository_name,
           evidence_source.github_check_subject_id,
           evidence_source.github_check_head_sha,
           inbox_source.accepted_at_ms,
           inbox_source.state AS inbox_state,
           manifest_source.workflow_selection_kind,
           manifest_source.check_subject_key,
           manifest_source.github_app_id,
           manifest_source.check_name,
           manifest_source.manifest_digest
      INTO authority
    FROM github_provider_delivery_evidence AS evidence_source
    JOIN provider_delivery_inbox AS inbox_source
      ON inbox_source.id = evidence_source.provider_delivery_id
     AND inbox_source.tenant_id = evidence_source.tenant_id
    JOIN github_provider_manifest_revisions AS manifest_source
      ON manifest_source.tenant_id = evidence_source.tenant_id
     AND manifest_source.repository_id = evidence_source.repository_id
     AND manifest_source.provider_connection_id = evidence_source.provider_connection_id
     AND manifest_source.manifest_revision = evidence_source.provider_manifest_revision
     AND manifest_source.manifest_digest = evidence_source.provider_manifest_digest
    WHERE evidence_source.provider_delivery_id = NEW.provider_delivery_id
      AND evidence_source.tenant_id = NEW.tenant_id
    FOR SHARE OF evidence_source, inbox_source, manifest_source;

    IF FOUND
       AND authority.workflow_selection_kind = 'all_direct'
       AND NEW.id <> authority.github_check_subject_id
    THEN
        SELECT TRUE INTO workflow_authorized
        FROM provider_delivery_workflow_inventories AS inventory
        JOIN provider_delivery_workflow_inventory_entries AS entry
          ON entry.inbox_id = inventory.inbox_id
         AND entry.tenant_id = inventory.tenant_id
        WHERE inventory.inbox_id = NEW.provider_delivery_id
          AND inventory.tenant_id = NEW.tenant_id
          AND inventory.manifest_digest = authority.manifest_digest
          AND entry.workflow_path = NEW.subject_key
          AND (
              entry.source_state = 'ready'
              OR EXISTS (
                  SELECT 1
                  FROM provider_delivery_workflow_progress AS progress
                  WHERE progress.inbox_id = inventory.inbox_id
                    AND progress.tenant_id = inventory.tenant_id
                    AND progress.inventory_digest = inventory.inventory_digest
                    AND progress.workflow_path = entry.workflow_path
                    AND progress.outcome_kind = 'failed'
              )
          )
        FOR SHARE OF inventory, entry;
    END IF;

    IF authority.repository_id IS NULL
        OR NEW.origin_kind <> 'provider_delivery'
        OR NEW.repository_id <> authority.repository_id
        OR NEW.provider_connection_id <> authority.provider_connection_id
        OR NEW.provider_installation_id <> authority.provider_installation_id
        OR NEW.github_repository_id <> authority.github_repository_id
        OR NEW.github_repository_name <> authority.github_repository_name
        OR NEW.github_app_id <> authority.github_app_id
        OR NEW.head_sha <> authority.github_check_head_sha
        OR NEW.check_name <> authority.check_name
        OR NEW.created_at_ms <> authority.accepted_at_ms
        OR NOT (
            NEW.id = authority.github_check_subject_id
            AND NEW.subject_key = authority.check_subject_key
            OR authority.workflow_selection_kind = 'all_direct'
            AND authority.inbox_state = 'claimed'
            AND NEW.id <> authority.github_check_subject_id
            AND workflow_authorized
        )
    THEN
        RAISE EXCEPTION 'GitHub Check subject does not match its signed delivery evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_delivery_evidence_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_github_check_subject_insert_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    schedule RECORD;
    now_ms BIGINT;
BEGIN
    IF NEW.desired_state <> 'queued'
        OR NEW.desired_revision <> 1
        OR NEW.desired_updated_at_ms <> NEW.created_at_ms
        OR NEW.workflow_run_id IS NOT NULL
        OR NEW.linked_at_ms IS NOT NULL
    THEN
        RAISE EXCEPTION 'GitHub Check subjects must begin queued and unlinked'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_initial_state';
    END IF;

    SELECT * INTO repository
    FROM repositories
    WHERE id = NEW.repository_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    IF repository.id IS NULL
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner || '/' || repository.name <> NEW.github_repository_name
    THEN
        RAISE EXCEPTION 'GitHub Check subject repository is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_authority_exact';
    END IF;

    IF NEW.origin_kind = 'provider_delivery' THEN
        SELECT * INTO delivery
        FROM provider_delivery_inbox
        WHERE id = NEW.provider_delivery_id
          AND tenant_id = NEW.tenant_id
        FOR SHARE;
        IF delivery.id IS NULL
            OR delivery.provider <> 'github'
            OR delivery.connection_id <> NEW.provider_connection_id
            OR delivery.installation_id <> NEW.provider_installation_id
            OR delivery.provider_repository_id <> NEW.github_repository_id
        THEN
            RAISE EXCEPTION 'GitHub Check delivery authority is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_authority_exact';
        END IF;
    ELSIF NEW.origin_kind = 'scheduled_fire' THEN
        now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
        SELECT fire.fire_id,
               fire.state AS fire_state,
               fire.claimed_at_ms,
               fire.claim_expires_at_ms,
               registry.source_revision,
               registry.default_branch_ref,
               entry.workflow_path,
               seal.registry_id AS sealed_registry_id,
               current.registry_id AS current_registry_id,
               manifest.provider_installation_id,
               manifest.github_repository_id,
               manifest.github_repository_name,
               manifest.github_app_id,
               manifest.check_name,
               manifest.git_ref
          INTO schedule
        FROM github_schedule_fires AS fire
        JOIN github_schedule_registry_revisions AS registry
          ON registry.tenant_id = fire.tenant_id
         AND registry.repository_id = fire.repository_id
         AND registry.provider_connection_id = fire.provider_connection_id
         AND registry.registry_id = fire.registry_id
        JOIN github_schedule_registry_entries AS entry
          ON entry.registry_id = fire.registry_id
         AND entry.ordinal = fire.entry_ordinal
        JOIN github_schedule_registry_seals AS seal
          ON seal.registry_id = registry.registry_id
         AND seal.inventory_digest = registry.inventory_digest
         AND seal.schedule_count = registry.schedule_count
        JOIN github_schedule_registry_current AS current
          ON current.tenant_id = registry.tenant_id
         AND current.repository_id = registry.repository_id
         AND current.provider_connection_id = registry.provider_connection_id
         AND current.registry_id = registry.registry_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = registry.tenant_id
         AND manifest.repository_id = registry.repository_id
         AND manifest.provider_connection_id = registry.provider_connection_id
         AND manifest.manifest_revision = registry.manifest_revision
         AND manifest.manifest_digest = registry.manifest_digest
        JOIN github_provider_manifest_current AS manifest_current
          ON manifest_current.tenant_id = manifest.tenant_id
         AND manifest_current.repository_id = manifest.repository_id
         AND manifest_current.provider_connection_id = manifest.provider_connection_id
         AND manifest_current.manifest_revision = manifest.manifest_revision
         AND manifest_current.manifest_digest = manifest.manifest_digest
        WHERE fire.fire_id = NEW.schedule_fire_id
          AND fire.tenant_id = NEW.tenant_id
          AND fire.repository_id = NEW.repository_id
          AND fire.provider_connection_id = NEW.provider_connection_id
        FOR SHARE OF fire, registry, entry, seal, current, manifest, manifest_current;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'GitHub scheduled Check has no exact sealed fire'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_schedule_authority_exact';
        END IF;
        IF schedule.fire_state <> 'claimed'
            OR schedule.claimed_at_ms > now_ms
            OR schedule.claim_expires_at_ms <= now_ms
            OR NEW.created_at_ms < schedule.claimed_at_ms
            OR NEW.created_at_ms >= schedule.claim_expires_at_ms
            OR schedule.default_branch_ref <> schedule.git_ref
            OR NEW.subject_key <> schedule.workflow_path
            OR NEW.provider_installation_id <> schedule.provider_installation_id
            OR NEW.github_repository_id <> schedule.github_repository_id
            OR NEW.github_repository_name <> schedule.github_repository_name
            OR NEW.github_app_id <> schedule.github_app_id
            OR NEW.head_sha <> decode(schedule.source_revision, 'hex')
            OR NEW.check_name <> schedule.check_name
        THEN
            RAISE EXCEPTION 'GitHub scheduled Check authority is not exact and live'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_schedule_authority_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub Check subject origin is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TABLE github_schedule_check_evidence (
    schedule_fire_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    registry_id UUID NOT NULL,
    entry_ordinal SMALLINT NOT NULL,
    scheduled_at_ms BIGINT NOT NULL,
    provider_manifest_revision BIGINT NOT NULL,
    provider_manifest_digest BYTEA NOT NULL,
    default_branch_ref TEXT COLLATE "C" NOT NULL,
    source_revision TEXT COLLATE "C" NOT NULL,
    github_repository_owner_id BIGINT NOT NULL,
    checks_authority_id UUID NOT NULL,
    checks_authority_identity_digest BYTEA NOT NULL,
    checks_authority_app_configuration_revision BIGINT NOT NULL,
    checks_authority_policy_revision BIGINT NOT NULL,
    github_check_subject_id UUID NOT NULL,
    github_check_head_sha BYTEA NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    CONSTRAINT github_schedule_check_evidence_subject_unique
        UNIQUE (github_check_subject_id),
    CONSTRAINT github_schedule_check_evidence_fire
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id, schedule_fire_id,
            registry_id, entry_ordinal, scheduled_at_ms
        ) REFERENCES github_schedule_fires(
            tenant_id, repository_id, provider_connection_id, fire_id,
            registry_id, entry_ordinal, scheduled_at_ms
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_check_evidence_registry
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id, registry_id,
            provider_manifest_revision, provider_manifest_digest,
            default_branch_ref, source_revision, github_repository_owner_id
        ) REFERENCES github_schedule_registry_revisions(
            tenant_id, repository_id, provider_connection_id, registry_id,
            manifest_revision, manifest_digest, default_branch_ref, source_revision,
            github_repository_owner_id
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_check_evidence_entry
        FOREIGN KEY (registry_id, entry_ordinal)
        REFERENCES github_schedule_registry_entries(registry_id, ordinal)
        ON DELETE RESTRICT,
    CONSTRAINT github_schedule_check_evidence_manifest
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            provider_manifest_revision, provider_manifest_digest
        ) REFERENCES github_provider_manifest_revisions(
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_check_evidence_checks_authority
        FOREIGN KEY (tenant_id, checks_authority_id)
        REFERENCES github_server_service_authorities(tenant_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT github_schedule_check_evidence_subject
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            schedule_fire_id, github_check_subject_id
        ) REFERENCES github_check_subjects(
            tenant_id, repository_id, provider_connection_id,
            schedule_fire_id, id
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT github_schedule_check_evidence_non_nil CHECK (
        schedule_fire_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND provider_connection_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND registry_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND checks_authority_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND github_check_subject_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT github_schedule_check_evidence_shape CHECK (
        entry_ordinal BETWEEN 0 AND 255
        AND scheduled_at_ms >= 0
        AND provider_manifest_revision > 0
        AND github_repository_owner_id > 0
        AND octet_length(provider_manifest_digest) = 32
        AND octet_length(checks_authority_identity_digest) = 32
        AND checks_authority_app_configuration_revision > 0
        AND checks_authority_policy_revision > 0
        AND source_revision ~ '^[0-9a-f]{40}$'
        AND automata_github_provider_git_ref_canonical(default_branch_ref)
        AND octet_length(github_check_head_sha) = 20
        AND github_check_head_sha = decode(source_revision, 'hex')
        AND recorded_at_ms >= 0
    )
);

CREATE FUNCTION automata_github_schedule_check_evidence_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    exact BOOLEAN;
    now_ms BIGINT;
BEGIN
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT TRUE INTO exact
    FROM github_schedule_fires AS fire
    JOIN github_schedule_registry_revisions AS registry
      ON registry.tenant_id = fire.tenant_id
     AND registry.repository_id = fire.repository_id
     AND registry.provider_connection_id = fire.provider_connection_id
     AND registry.registry_id = fire.registry_id
    JOIN github_schedule_registry_entries AS entry
      ON entry.registry_id = fire.registry_id
     AND entry.ordinal = fire.entry_ordinal
    JOIN github_schedule_registry_seals AS seal
      ON seal.registry_id = registry.registry_id
     AND seal.inventory_digest = registry.inventory_digest
     AND seal.schedule_count = registry.schedule_count
    JOIN github_schedule_registry_current AS current
      ON current.tenant_id = registry.tenant_id
     AND current.repository_id = registry.repository_id
     AND current.provider_connection_id = registry.provider_connection_id
     AND current.registry_id = registry.registry_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = registry.tenant_id
     AND manifest.repository_id = registry.repository_id
     AND manifest.provider_connection_id = registry.provider_connection_id
     AND manifest.manifest_revision = registry.manifest_revision
     AND manifest.manifest_digest = registry.manifest_digest
    JOIN github_provider_manifest_current AS manifest_current
      ON manifest_current.tenant_id = manifest.tenant_id
     AND manifest_current.repository_id = manifest.repository_id
     AND manifest_current.provider_connection_id = manifest.provider_connection_id
     AND manifest_current.manifest_revision = manifest.manifest_revision
     AND manifest_current.manifest_digest = manifest.manifest_digest
    JOIN github_server_service_authorities AS authority
      ON authority.tenant_id = registry.tenant_id
     AND authority.id = NEW.checks_authority_id
    JOIN github_check_subjects AS subject
      ON subject.tenant_id = fire.tenant_id
     AND subject.repository_id = fire.repository_id
     AND subject.provider_connection_id = fire.provider_connection_id
     AND subject.schedule_fire_id = fire.fire_id
     AND subject.id = NEW.github_check_subject_id
    WHERE fire.fire_id = NEW.schedule_fire_id
      AND fire.tenant_id = NEW.tenant_id
      AND fire.repository_id = NEW.repository_id
      AND fire.provider_connection_id = NEW.provider_connection_id
      AND fire.registry_id = NEW.registry_id
      AND fire.entry_ordinal = NEW.entry_ordinal
      AND fire.scheduled_at_ms = NEW.scheduled_at_ms
      AND fire.state = 'claimed'
      AND fire.claimed_at_ms <= now_ms
      AND fire.claim_expires_at_ms > now_ms
      AND NEW.recorded_at_ms >= fire.claimed_at_ms
      AND NEW.recorded_at_ms < fire.claim_expires_at_ms
      AND registry.manifest_revision = NEW.provider_manifest_revision
      AND registry.manifest_digest = NEW.provider_manifest_digest
      AND registry.default_branch_ref = NEW.default_branch_ref
      AND registry.source_revision = NEW.source_revision
      AND registry.github_repository_owner_id = NEW.github_repository_owner_id
      AND registry.default_branch_ref = manifest.git_ref
      AND NEW.github_check_head_sha = decode(registry.source_revision, 'hex')
      AND subject.origin_kind = 'scheduled_fire'
      AND subject.provider_delivery_id IS NULL
      AND subject.subject_key = entry.workflow_path
      AND subject.provider_installation_id = manifest.provider_installation_id
      AND subject.github_repository_id = manifest.github_repository_id
      AND subject.github_repository_name = manifest.github_repository_name
      AND subject.github_app_id = manifest.github_app_id
      AND subject.head_sha = NEW.github_check_head_sha
      AND subject.check_name = manifest.check_name
      AND subject.created_at_ms = NEW.recorded_at_ms
      AND authority.repository_id = registry.repository_id
      AND authority.provider_connection_id = registry.provider_connection_id
      AND authority.provider_installation_id = manifest.provider_installation_id
      AND authority.github_app_id = manifest.github_app_id
      AND authority.github_repository_id = manifest.github_repository_id
      AND authority.github_repository_name = manifest.github_repository_name
      AND authority.service_scope = 'checks_write'
      AND authority.github_app_client_id = manifest.github_app_client_id
      AND authority.github_app_jwt_issuer_kind = manifest.github_app_jwt_issuer_kind
      AND authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
      AND authority.app_configuration_revision =
          NEW.checks_authority_app_configuration_revision
      AND authority.app_configuration_revision = manifest.app_configuration_revision
      AND authority.policy_revision = NEW.checks_authority_policy_revision
      AND authority.policy_revision = manifest.policy_revision
      AND authority.identity_digest = NEW.checks_authority_identity_digest
      AND authority.state = 'active'
      AND authority.created_at_ms <= NEW.recorded_at_ms
    FOR SHARE OF fire, registry, entry, seal, current, manifest, manifest_current,
                 authority, subject;
    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'GitHub schedule Check evidence is not exact and live'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_check_evidence_authority_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_schedule_check_evidence_00_insert_guard
BEFORE INSERT ON github_schedule_check_evidence
FOR EACH ROW EXECUTE FUNCTION automata_github_schedule_check_evidence_insert_guard();

CREATE FUNCTION automata_github_schedule_check_requires_atomic_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    evidence github_schedule_check_evidence%ROWTYPE;
    outbox github_check_projection_outbox%ROWTYPE;
BEGIN
    IF NEW.origin_kind <> 'scheduled_fire' THEN
        RETURN NULL;
    END IF;
    SELECT * INTO evidence
    FROM github_schedule_check_evidence
    WHERE schedule_fire_id = NEW.schedule_fire_id
      AND tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND provider_connection_id = NEW.provider_connection_id
      AND github_check_subject_id = NEW.id;
    SELECT * INTO outbox
    FROM github_check_projection_outbox
    WHERE subject_id = NEW.id;
    IF evidence.schedule_fire_id IS NULL
        OR evidence.github_check_head_sha <> NEW.head_sha
        OR evidence.recorded_at_ms <> NEW.created_at_ms
        OR outbox.subject_id IS NULL
        OR outbox.state <> 'pending'
        OR outbox.attempted_revision IS NOT NULL
        OR outbox.attempt_count <> 0
        OR outbox.claim_fence <> 0
        OR outbox.projected_revision <> 0
        OR outbox.state_updated_at_ms <> NEW.created_at_ms
    THEN
        RAISE EXCEPTION 'GitHub scheduled Check requires atomic sealed evidence and outbox'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_check_atomic_evidence_required';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER github_check_subjects_require_atomic_schedule_evidence
AFTER INSERT ON github_check_subjects
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_github_schedule_check_requires_atomic_evidence();

CREATE FUNCTION automata_github_schedule_run_subject_evidence_digest(
    schedule_fire_id UUID,
    tenant_id TEXT,
    repository_id UUID,
    workflow_id UUID,
    snapshot_id UUID,
    run_id UUID,
    root_invocation_id UUID,
    github_repository_owner_id BIGINT,
    admission_claim_owner_id UUID,
    admission_claim_attempt SMALLINT,
    admission_claim_fence BIGINT,
    admission_claimed_at_ms BIGINT,
    admission_claim_expires_at_ms BIGINT,
    github_check_subject_id UUID,
    github_check_head_sha BYTEA,
    workflow_path TEXT,
    source_digest BYTEA,
    event_name TEXT,
    event_digest BYTEA,
    git_ref TEXT,
    workflow_plan_schema SMALLINT,
    plan_digest BYTEA,
    logical_admission_digest BYTEA,
    admitted_at_ms BIGINT
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.github-schedule-run-subject-evidence.v1', 'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(schedule_fire_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(tenant_id, 'UTF8'))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(repository_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(workflow_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(snapshot_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(run_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(root_invocation_id))
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(github_repository_owner_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(admission_claim_owner_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(admission_claim_attempt::BIGINT)
    )
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(admission_claim_fence))
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(admission_claimed_at_ms))
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(admission_claim_expires_at_ms)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(github_check_subject_id)
    )
    || automata_github_provider_manifest_digest_part(github_check_head_sha)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(workflow_path, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(source_digest)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(event_name, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(event_digest)
    || automata_github_provider_manifest_digest_part(pg_catalog.convert_to(git_ref, 'UTF8'))
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(workflow_plan_schema::BIGINT)
    )
    || automata_github_provider_manifest_digest_part(plan_digest)
    || automata_github_provider_manifest_digest_part(logical_admission_digest)
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(admitted_at_ms))
)
$automata$;

CREATE TABLE github_schedule_workflow_run_subject_evidence (
    schedule_fire_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    workflow_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,
    run_id UUID NOT NULL,
    root_invocation_id UUID NOT NULL,
    github_repository_owner_id BIGINT NOT NULL,
    admission_claim_owner_id UUID NOT NULL,
    admission_claim_attempt SMALLINT NOT NULL,
    admission_claim_fence BIGINT NOT NULL,
    admission_claimed_at_ms BIGINT NOT NULL,
    admission_claim_expires_at_ms BIGINT NOT NULL,
    github_check_subject_id UUID NOT NULL,
    github_check_head_sha BYTEA NOT NULL,
    workflow_path TEXT COLLATE "C" NOT NULL,
    source_digest BYTEA NOT NULL,
    event_name TEXT COLLATE "C" NOT NULL,
    event_digest BYTEA NOT NULL,
    git_ref TEXT COLLATE "C" NOT NULL,
    workflow_plan_schema SMALLINT NOT NULL,
    plan_digest BYTEA NOT NULL,
    logical_admission_digest BYTEA NOT NULL,
    subject_evidence_sha256 BYTEA GENERATED ALWAYS AS (
        automata_github_schedule_run_subject_evidence_digest(
            schedule_fire_id, tenant_id, repository_id, workflow_id,
            snapshot_id, run_id, root_invocation_id, github_repository_owner_id,
            admission_claim_owner_id, admission_claim_attempt, admission_claim_fence,
            admission_claimed_at_ms, admission_claim_expires_at_ms,
            github_check_subject_id, github_check_head_sha, workflow_path,
            source_digest, event_name, event_digest, git_ref,
            workflow_plan_schema, plan_digest, logical_admission_digest, admitted_at_ms
        )
    ) STORED,
    admitted_at_ms BIGINT NOT NULL,
    CONSTRAINT github_schedule_workflow_run_subject_evidence_run_unique
        UNIQUE (repository_id, run_id),
    CONSTRAINT github_schedule_workflow_run_subject_evidence_subject_unique
        UNIQUE (github_check_subject_id),
    CONSTRAINT github_schedule_workflow_run_subject_evidence_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_workflow_run_subject_evidence_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_workflow_run_subject_evidence_workflow
        FOREIGN KEY (repository_id, workflow_id)
        REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_workflow_run_subject_evidence_snapshot
        FOREIGN KEY (snapshot_id, workflow_id)
        REFERENCES workflow_snapshots(id, workflow_id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_workflow_run_subject_evidence_fire
        FOREIGN KEY (
            tenant_id, repository_id, schedule_fire_id
        ) REFERENCES github_schedule_fires(
            tenant_id, repository_id, fire_id
        ) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_workflow_run_subject_evidence_check
        FOREIGN KEY (tenant_id, github_check_subject_id)
        REFERENCES github_check_subjects(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_schedule_workflow_run_subject_evidence_non_nil CHECK (
        schedule_fire_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND workflow_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND snapshot_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND run_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND root_invocation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND admission_claim_owner_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND github_check_subject_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT github_schedule_workflow_run_subject_evidence_shape CHECK (
        admission_claim_attempt BETWEEN 1 AND 20
        AND github_repository_owner_id > 0
        AND admission_claim_fence > 0
        AND admission_claimed_at_ms >= 0
        AND admission_claim_expires_at_ms > admission_claimed_at_ms
        AND admitted_at_ms >= admission_claimed_at_ms
        AND admitted_at_ms < admission_claim_expires_at_ms
        AND octet_length(github_check_head_sha) = 20
        AND octet_length(source_digest) = 32
        AND event_name = 'schedule'
        AND octet_length(event_digest) = 32
        AND automata_github_provider_git_ref_canonical(git_ref)
        AND workflow_plan_schema = 2
        AND octet_length(plan_digest) = 32
        AND octet_length(logical_admission_digest) = 32
        AND octet_length(subject_evidence_sha256) = 32
        AND workflow_path ~ '^\.github/workflows/[^/]+\.ya?ml$'
        AND workflow_path !~ '[[:cntrl:]\\]'
    )
);

CREATE FUNCTION automata_github_schedule_run_evidence_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    exact BOOLEAN;
    now_ms BIGINT;
BEGIN
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT TRUE INTO exact
    FROM github_schedule_fires AS fire
    JOIN github_schedule_registry_revisions AS registry
      ON registry.tenant_id = fire.tenant_id
     AND registry.repository_id = fire.repository_id
     AND registry.provider_connection_id = fire.provider_connection_id
     AND registry.registry_id = fire.registry_id
    JOIN github_schedule_registry_entries AS entry
     ON entry.registry_id = fire.registry_id
     AND entry.ordinal = fire.entry_ordinal
    JOIN github_provider_manifest_current AS manifest_current
      ON manifest_current.tenant_id = registry.tenant_id
     AND manifest_current.repository_id = registry.repository_id
     AND manifest_current.provider_connection_id = registry.provider_connection_id
     AND manifest_current.manifest_revision = registry.manifest_revision
     AND manifest_current.manifest_digest = registry.manifest_digest
    JOIN github_schedule_check_evidence AS schedule_check
      ON schedule_check.schedule_fire_id = fire.fire_id
     AND schedule_check.tenant_id = fire.tenant_id
     AND schedule_check.repository_id = fire.repository_id
     AND schedule_check.provider_connection_id = fire.provider_connection_id
     AND schedule_check.registry_id = fire.registry_id
     AND schedule_check.entry_ordinal = fire.entry_ordinal
    JOIN github_check_subjects AS check_subject
      ON check_subject.id = schedule_check.github_check_subject_id
     AND check_subject.tenant_id = schedule_check.tenant_id
    JOIN workflow_runs AS run
      ON run.repository_id = fire.repository_id
     AND run.id = NEW.run_id
    JOIN workflow_definitions AS workflow
      ON workflow.repository_id = run.repository_id
     AND workflow.id = run.workflow_id
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
    JOIN workflow_plan_v2_runs AS marker
      ON marker.run_id = run.id
    JOIN workflow_admission_receipts AS admission
      ON admission.tenant_id = fire.tenant_id
     AND admission.idempotency_kind = 'operation'
     AND admission.idempotency_key = fire.fire_id::TEXT
     AND admission.repository_id = fire.repository_id
     AND admission.run_id = run.id
    WHERE fire.fire_id = NEW.schedule_fire_id
      AND fire.tenant_id = NEW.tenant_id
      AND fire.repository_id = NEW.repository_id
      AND fire.state = 'claimed'
      AND fire.claim_owner_id = NEW.admission_claim_owner_id
      AND fire.attempt_count = NEW.admission_claim_attempt
      AND fire.claim_fence = NEW.admission_claim_fence
      AND fire.claimed_at_ms = NEW.admission_claimed_at_ms
      AND fire.claim_expires_at_ms = NEW.admission_claim_expires_at_ms
      AND fire.claimed_at_ms <= now_ms
      AND fire.claim_expires_at_ms > now_ms
      AND registry.default_branch_ref = schedule_check.default_branch_ref
      AND registry.source_revision = schedule_check.source_revision
      AND registry.github_repository_owner_id = NEW.github_repository_owner_id
      AND schedule_check.github_repository_owner_id = NEW.github_repository_owner_id
      AND entry.workflow_path = NEW.workflow_path
      AND entry.workflow_source_digest = NEW.source_digest
      AND check_subject.origin_kind = 'scheduled_fire'
      AND check_subject.schedule_fire_id = fire.fire_id
      AND check_subject.provider_delivery_id IS NULL
      AND check_subject.workflow_run_id = run.id
      AND check_subject.linked_at_ms = NEW.admitted_at_ms
      AND check_subject.desired_state = 'in_progress'
      AND check_subject.head_sha = NEW.github_check_head_sha
      AND schedule_check.github_check_subject_id = NEW.github_check_subject_id
      AND schedule_check.github_check_head_sha = NEW.github_check_head_sha
      AND run.workflow_id = NEW.workflow_id
      AND run.snapshot_id = NEW.snapshot_id
      AND run.head_sha = NEW.github_check_head_sha
      AND run.git_ref = registry.default_branch_ref
      AND run.git_ref = NEW.git_ref
      AND run.event_name = 'schedule'
      AND run.event_name = NEW.event_name
      AND run.event_digest = NEW.event_digest
      AND run.plan_schema = NEW.workflow_plan_schema
      AND run.plan_digest = NEW.plan_digest
      AND run.created_at_ms = NEW.admitted_at_ms
      AND workflow.path = NEW.workflow_path
      AND snapshot.source_digest = NEW.source_digest
      AND marker.root_invocation_id = NEW.root_invocation_id
      AND marker.admission_digest = NEW.logical_admission_digest
      AND marker.admitted_at_ms = NEW.admitted_at_ms
      AND admission.request_digest = NEW.logical_admission_digest
      AND admission.committed_at_ms = NEW.admitted_at_ms
      AND admission.github_subject_evidence_required
    FOR SHARE OF fire, registry, entry, manifest_current, schedule_check, check_subject,
                 run, workflow, snapshot, marker, admission;
    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'GitHub scheduled run evidence is not exact and live'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_run_evidence_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_schedule_workflow_run_subject_evidence_00_insert_guard
BEFORE INSERT ON github_schedule_workflow_run_subject_evidence
FOR EACH ROW EXECUTE FUNCTION automata_github_schedule_run_evidence_insert_guard();

-- One typed, read-only manifest-origin projection feeds logical lifecycle
-- consumers. Each branch retains its native key and evidence table.
CREATE VIEW github_workflow_run_manifest_origins AS
SELECT delivery_run.tenant_id,
       delivery_run.repository_id,
       delivery_run.workflow_id,
       delivery_run.snapshot_id,
       delivery_run.run_id,
       delivery_run.root_invocation_id,
       'provider_delivery'::TEXT AS origin_kind,
       delivery_run.provider_delivery_id AS origin_id,
       'provider_delivery'::TEXT AS admission_idempotency_kind,
       delivery_run.provider_delivery_idempotency_key AS admission_idempotency_key,
       delivery_run.github_check_subject_id,
       delivery_run.github_check_head_sha,
       delivery_run.workflow_path,
       delivery_run.source_digest,
       delivery_run.event_name,
       delivery_run.event_digest,
       delivery_run.git_ref,
       delivery_run.workflow_plan_schema,
       delivery_run.plan_digest,
       delivery_run.logical_admission_digest,
       delivery_run.admitted_at_ms,
       delivery_run.subject_evidence_sha256,
       delivery.provider_connection_id,
       delivery.provider_installation_id,
       delivery.github_repository_id,
       delivery.github_repository_owner_id,
       delivery.github_repository_name,
       delivery.repository_visibility,
       delivery.provider_manifest_revision,
       delivery.provider_manifest_digest,
       delivery.authenticated_webhook_verifier_fingerprint_sha256,
       delivery.authenticated_webhook_verifier_revision,
       delivery.checks_authority_id,
       delivery.checks_authority_identity_digest,
       delivery.checks_authority_app_configuration_revision,
       delivery.checks_authority_policy_revision,
       delivery.private_source_authority_id,
       delivery.private_source_authority_identity_digest,
       delivery.private_source_authority_app_configuration_revision,
       delivery.private_source_authority_policy_revision
FROM github_workflow_run_subject_evidence AS delivery_run
JOIN github_provider_delivery_evidence AS delivery
  ON delivery.tenant_id = delivery_run.tenant_id
 AND delivery.repository_id = delivery_run.repository_id
 AND delivery.provider_delivery_id = delivery_run.provider_delivery_id
UNION ALL
SELECT schedule_run.tenant_id,
       schedule_run.repository_id,
       schedule_run.workflow_id,
       schedule_run.snapshot_id,
       schedule_run.run_id,
       schedule_run.root_invocation_id,
       'scheduled_fire'::TEXT AS origin_kind,
       schedule_run.schedule_fire_id AS origin_id,
       'operation'::TEXT AS admission_idempotency_kind,
       schedule_run.schedule_fire_id::TEXT AS admission_idempotency_key,
       schedule_run.github_check_subject_id,
       schedule_run.github_check_head_sha,
       schedule_run.workflow_path,
       schedule_run.source_digest,
       schedule_run.event_name,
       schedule_run.event_digest,
       schedule_run.git_ref,
       schedule_run.workflow_plan_schema,
       schedule_run.plan_digest,
       schedule_run.logical_admission_digest,
       schedule_run.admitted_at_ms,
       schedule_run.subject_evidence_sha256,
       schedule_check.provider_connection_id,
       manifest.provider_installation_id,
       manifest.github_repository_id,
       schedule_run.github_repository_owner_id,
       manifest.github_repository_name,
       manifest.repository_visibility,
       schedule_check.provider_manifest_revision,
       schedule_check.provider_manifest_digest,
       manifest.webhook_verifier_fingerprint_sha256,
       manifest.webhook_verifier_revision,
       schedule_check.checks_authority_id,
       schedule_check.checks_authority_identity_digest,
       schedule_check.checks_authority_app_configuration_revision,
       schedule_check.checks_authority_policy_revision,
       registry.private_source_authority_id,
       registry.private_source_authority_identity_digest,
       registry.private_source_authority_app_configuration_revision,
       registry.private_source_authority_policy_revision
FROM github_schedule_workflow_run_subject_evidence AS schedule_run
JOIN github_schedule_check_evidence AS schedule_check
  ON schedule_check.schedule_fire_id = schedule_run.schedule_fire_id
 AND schedule_check.tenant_id = schedule_run.tenant_id
 AND schedule_check.repository_id = schedule_run.repository_id
 AND schedule_check.github_check_subject_id = schedule_run.github_check_subject_id
JOIN github_schedule_registry_revisions AS registry
  ON registry.tenant_id = schedule_check.tenant_id
 AND registry.repository_id = schedule_check.repository_id
 AND registry.provider_connection_id = schedule_check.provider_connection_id
 AND registry.registry_id = schedule_check.registry_id
 AND registry.manifest_revision = schedule_check.provider_manifest_revision
 AND registry.manifest_digest = schedule_check.provider_manifest_digest
 AND registry.default_branch_ref = schedule_check.default_branch_ref
 AND registry.source_revision = schedule_check.source_revision
JOIN github_provider_manifest_revisions AS manifest
  ON manifest.tenant_id = schedule_check.tenant_id
 AND manifest.repository_id = schedule_check.repository_id
 AND manifest.provider_connection_id = schedule_check.provider_connection_id
 AND manifest.manifest_revision = schedule_check.provider_manifest_revision
 AND manifest.manifest_digest = schedule_check.provider_manifest_digest;

-- Runtime-policy pin provenance predates scheduled subjects and originally
-- accepted delivery evidence only. Keep one sealed manifest-origin boundary
-- for both closed origin variants; callers cannot manufacture an origin row.
CREATE OR REPLACE FUNCTION automata_require_workflow_runtime_policy_pin_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = origin.run_id
    WHERE origin.run_id = NEW.run_id
      AND origin.tenant_id = NEW.tenant_id
      AND origin.repository_id = NEW.repository_id
      AND origin.admitted_at_ms = NEW.pinned_at_ms
      AND manifest.runtime_policy_revision = NEW.policy_revision
      AND manifest.runtime_policy_digest = NEW.policy_digest
    FOR SHARE OF manifest, policy, run, marker;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow runtime policy pin lacks authenticated manifest provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_runtime_policy_pin_provenance';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_pin_github_scheduled_workflow_runtime_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    rows_inserted BIGINT;
BEGIN
    INSERT INTO workflow_plan_v2_runtime_policy_pins (
        run_id, tenant_id, repository_id, policy_revision,
        policy_digest, pinned_at_ms
    )
    SELECT NEW.run_id, NEW.tenant_id, NEW.repository_id,
           manifest.runtime_policy_revision, manifest.runtime_policy_digest,
           NEW.admitted_at_ms
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
    WHERE origin.origin_kind = 'scheduled_fire'
      AND origin.origin_id = NEW.schedule_fire_id
      AND origin.run_id = NEW.run_id
      AND origin.tenant_id = NEW.tenant_id
      AND origin.repository_id = NEW.repository_id;
    GET DIAGNOSTICS rows_inserted = ROW_COUNT;
    IF rows_inserted <> 1 THEN
        RAISE EXCEPTION 'scheduled GitHub WorkflowPlan-v2 run lacks its historical manifest runtime policy'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_runtime_policy_pin_required';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_schedule_workflow_run_subject_evidence_10_pin_runtime_policy
AFTER INSERT ON github_schedule_workflow_run_subject_evidence
FOR EACH ROW EXECUTE FUNCTION automata_pin_github_scheduled_workflow_runtime_policy();

-- Extend the deferred admission/evidence seal introduced for webhook
-- deliveries to the operation-idempotent scheduled admission path.
CREATE OR REPLACE FUNCTION automata_required_github_subject_evidence_committed()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    receipt workflow_admission_receipts%ROWTYPE;
    evidence_count BIGINT;
BEGIN
    IF NOT NEW.github_subject_evidence_required THEN
        RETURN NULL;
    END IF;

    SELECT * INTO receipt
    FROM workflow_admission_receipts
    WHERE tenant_id = NEW.tenant_id
      AND idempotency_kind = NEW.idempotency_kind
      AND idempotency_key = NEW.idempotency_key;

    IF receipt.github_subject_evidence_required
        AND receipt.idempotency_kind = 'provider_delivery'
        AND receipt.repository_id IS NOT NULL
        AND receipt.run_id IS NOT NULL
        AND receipt.committed_at_ms IS NOT NULL
    THEN
        SELECT count(*) INTO evidence_count
        FROM github_workflow_run_subject_evidence AS evidence
        WHERE evidence.tenant_id = receipt.tenant_id
          AND evidence.repository_id = receipt.repository_id
          AND evidence.run_id = receipt.run_id
          AND evidence.provider_delivery_idempotency_key = receipt.idempotency_key
          AND evidence.logical_admission_digest = receipt.request_digest
          AND evidence.admitted_at_ms = receipt.committed_at_ms;
    ELSIF receipt.github_subject_evidence_required
        AND receipt.idempotency_kind = 'operation'
        AND receipt.repository_id IS NOT NULL
        AND receipt.run_id IS NOT NULL
        AND receipt.committed_at_ms IS NOT NULL
    THEN
        SELECT count(*) INTO evidence_count
        FROM github_schedule_workflow_run_subject_evidence AS evidence
        WHERE evidence.tenant_id = receipt.tenant_id
          AND evidence.repository_id = receipt.repository_id
          AND evidence.run_id = receipt.run_id
          AND evidence.schedule_fire_id::TEXT = receipt.idempotency_key
          AND evidence.logical_admission_digest = receipt.request_digest
          AND evidence.admitted_at_ms = receipt.committed_at_ms;
    END IF;

    IF evidence_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'authenticated GitHub admission requires exact subject evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_admission_required_github_evidence_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

-- Root graph publication must accept either signed webhook evidence or the
-- schedule-specific evidence inserted by the authenticated admission path.
-- Migration 0055 only knew about webhook subjects, which otherwise makes
-- every scheduled admission fail when its first logical job is inserted.
CREATE OR REPLACE FUNCTION automata_require_open_workflow_admission_graph()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN github_workflow_run_subject_evidence AS subject ON subject.run_id = marker.run_id
    JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND subject.admitted_at_ms = receipt.committed_at_ms
      AND pin.pinned_at_ms = subject.admitted_at_ms
    FOR KEY SHARE OF marker, receipt, subject, pin;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN github_schedule_workflow_run_subject_evidence AS subject
      ON subject.run_id = marker.run_id
    JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND subject.admitted_at_ms = receipt.committed_at_ms
      AND pin.pinned_at_ms = subject.admitted_at_ms
    FOR KEY SHARE OF marker, receipt, subject, pin;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_plan_v2_reusable_call_publications AS publication
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = publication.run_id
    WHERE publication.run_id = NEW.run_id
      AND publication.child_invocation_id = NEW.invocation_id
      AND publication.child_graph_sealed_at_ms IS NULL
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND marker.state IN ('pending', 'active')
      AND NOT EXISTS (
          SELECT 1 FROM workflow_plan_v2_run_result_claims AS claim
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
$automata$;

CREATE FUNCTION automata_guard_github_schedule_fire_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'GitHub schedule fire evidence cannot be deleted'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_fire_transition_exact';
    END IF;
    IF OLD.state IN ('admitted', 'skipped', 'failed')
        OR NEW.fire_id IS DISTINCT FROM OLD.fire_id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.registry_id IS DISTINCT FROM OLD.registry_id
        OR NEW.entry_ordinal IS DISTINCT FROM OLD.entry_ordinal
        OR NEW.scheduled_at_ms IS DISTINCT FROM OLD.scheduled_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.updated_at_ms < OLD.updated_at_ms
    THEN
        RAISE EXCEPTION 'GitHub schedule fire identity or terminal evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_fire_transition_exact';
    END IF;

    IF OLD.state = 'pending' THEN
        IF NEW.state = 'claimed' THEN
            IF NEW.attempt_count <> OLD.attempt_count + 1
                OR NEW.claim_fence <> OLD.claim_fence + 1
                OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
                OR NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id
                OR NEW.failure_kind IS DISTINCT FROM OLD.failure_kind
                OR NEW.claimed_at_ms IS DISTINCT FROM NEW.updated_at_ms
                OR NEW.claimed_at_ms < OLD.next_attempt_at_ms
                OR NEW.claim_expires_at_ms - NEW.updated_at_ms > 300000
            THEN
                RAISE EXCEPTION 'pending GitHub schedule fire claim transition is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSIF NEW.state = 'failed' THEN
            IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                OR NEW.claim_fence IS DISTINCT FROM OLD.claim_fence
                OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
                OR NEW.workflow_run_id IS NOT NULL
                OR NEW.failure_kind IS DISTINCT FROM 'registry_superseded'
            THEN
                RAISE EXCEPTION 'pending GitHub schedule fire terminal transition is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSE
            RAISE EXCEPTION 'pending GitHub schedule fire state transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_schedule_fire_transition_exact';
        END IF;
    ELSIF OLD.state = 'claimed' THEN
        IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
            OR NEW.claim_fence IS DISTINCT FROM OLD.claim_fence
        THEN
            RAISE EXCEPTION 'claimed GitHub schedule fire fence is immutable'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_schedule_fire_transition_exact';
        END IF;
        IF NEW.state = 'claimed' THEN
            IF NEW.claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
                OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
                OR NEW.claim_expires_at_ms <= OLD.claim_expires_at_ms
                OR NEW.claim_expires_at_ms - NEW.updated_at_ms > 300000
                OR NEW.updated_at_ms >= OLD.claim_expires_at_ms
                OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
                OR NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id
                OR NEW.failure_kind IS DISTINCT FROM OLD.failure_kind
            THEN
                RAISE EXCEPTION 'GitHub schedule fire renewal is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSIF NEW.state = 'pending' THEN
            IF NEW.claim_owner_id IS NOT NULL
                OR NEW.claimed_at_ms IS NOT NULL
                OR NEW.claim_expires_at_ms IS NOT NULL
                OR NEW.next_attempt_at_ms < NEW.updated_at_ms
                OR NEW.workflow_run_id IS NOT NULL
                OR NEW.failure_kind IS NOT NULL
            THEN
                RAISE EXCEPTION 'GitHub schedule fire retry transition is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSIF NEW.state IN ('admitted', 'skipped', 'failed') THEN
            IF NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
                OR (
                    NEW.failure_kind IS DISTINCT FROM 'registry_superseded'
                    AND NEW.failure_kind IS DISTINCT FROM
                        'github.schedule.attempts_exhausted'
                    AND NEW.updated_at_ms >= OLD.claim_expires_at_ms
                )
                OR NEW.failure_kind = 'github.schedule.attempts_exhausted'
                   AND OLD.attempt_count <> 20
            THEN
                RAISE EXCEPTION 'GitHub schedule fire completion transition is invalid'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_schedule_fire_transition_exact';
            END IF;
        ELSE
            RAISE EXCEPTION 'claimed GitHub schedule fire state transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_schedule_fire_transition_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub schedule fire state is unsupported'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_fire_transition_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_schedule_fires_transition_exact
BEFORE UPDATE OR DELETE ON github_schedule_fires
FOR EACH ROW EXECUTE FUNCTION automata_guard_github_schedule_fire_transition();

CREATE FUNCTION automata_require_github_schedule_fire_terminal_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    exact BOOLEAN;
BEGIN
    IF NEW.state NOT IN ('admitted', 'skipped', 'failed') THEN
        RETURN NULL;
    END IF;
    IF NEW.failure_kind = 'registry_superseded' THEN
        SELECT NOT EXISTS (
                   SELECT 1
                     FROM github_schedule_registry_current AS current
                    WHERE current.tenant_id = NEW.tenant_id
                      AND current.repository_id = NEW.repository_id
                      AND current.provider_connection_id = NEW.provider_connection_id
                      AND current.registry_id = NEW.registry_id
               )
               AND NOT EXISTS (
                   SELECT 1
                     FROM github_schedule_runtime AS runtime
                    WHERE runtime.tenant_id = NEW.tenant_id
                      AND runtime.repository_id = NEW.repository_id
                      AND runtime.provider_connection_id = NEW.provider_connection_id
                      AND runtime.registry_id = NEW.registry_id
                      AND runtime.entry_ordinal = NEW.entry_ordinal
               )
          INTO exact;
        IF exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'superseded GitHub schedule fire lacks an inactive registry'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_schedule_fire_terminal_evidence';
        END IF;
        IF NEW.attempt_count = 0 THEN
            RETURN NULL;
        END IF;
    END IF;

    SELECT EXISTS (
               SELECT 1
                 FROM github_schedule_fire_attempts AS attempt
                WHERE attempt.fire_id = NEW.fire_id
                  AND attempt.attempt = NEW.attempt_count
                  AND attempt.claim_fence = NEW.claim_fence
                  AND attempt.outcome = NEW.state
                  AND attempt.failure_kind IS NOT DISTINCT FROM NEW.failure_kind
           )
           AND CASE
               WHEN NEW.failure_kind IN (
                   'registry_superseded',
                   'github.schedule.registry_invalid'
               ) THEN
                   NOT EXISTS (
                       SELECT 1
                         FROM github_schedule_runtime AS runtime
                        WHERE runtime.tenant_id = NEW.tenant_id
                          AND runtime.repository_id = NEW.repository_id
                          AND runtime.provider_connection_id = NEW.provider_connection_id
                          AND runtime.registry_id = NEW.registry_id
                          AND runtime.entry_ordinal = NEW.entry_ordinal
                   )
               ELSE EXISTS (
                   SELECT 1
                     FROM github_schedule_runtime AS runtime
                    WHERE runtime.tenant_id = NEW.tenant_id
                      AND runtime.repository_id = NEW.repository_id
                      AND runtime.provider_connection_id = NEW.provider_connection_id
                      AND runtime.registry_id = NEW.registry_id
                      AND runtime.entry_ordinal = NEW.entry_ordinal
                      AND runtime.next_fire_at_ms > NEW.scheduled_at_ms
               )
           END
      INTO exact;
    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'terminal GitHub schedule fire lacks exact attempt and advancement evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_fire_terminal_evidence';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER github_schedule_fires_terminal_evidence
AFTER INSERT OR UPDATE ON github_schedule_fires
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_github_schedule_fire_terminal_evidence();

CREATE FUNCTION automata_reject_github_schedule_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'immutable GitHub schedule evidence cannot be mutated'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_schedule_immutable_evidence';
END;
$automata$;

CREATE TRIGGER github_schedule_registry_revisions_immutable
BEFORE UPDATE OR DELETE ON github_schedule_registry_revisions
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_schedule_immutable_mutation();

CREATE TRIGGER github_schedule_registry_entries_immutable
BEFORE UPDATE OR DELETE ON github_schedule_registry_entries
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_schedule_immutable_mutation();

CREATE TRIGGER github_schedule_registry_seals_immutable
BEFORE UPDATE OR DELETE ON github_schedule_registry_seals
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_schedule_immutable_mutation();

CREATE TRIGGER github_schedule_fire_attempts_immutable
BEFORE UPDATE OR DELETE ON github_schedule_fire_attempts
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_schedule_immutable_mutation();

CREATE TRIGGER github_schedule_check_evidence_immutable
BEFORE UPDATE OR DELETE ON github_schedule_check_evidence
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_schedule_immutable_mutation();

CREATE TRIGGER github_schedule_workflow_run_subject_evidence_immutable
BEFORE UPDATE OR DELETE ON github_schedule_workflow_run_subject_evidence
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_schedule_immutable_mutation();

CREATE FUNCTION automata_reject_github_schedule_evidence_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub schedule evidence cannot be truncated'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_schedule_evidence_truncate_forbidden';
END;
$automata$;

CREATE TRIGGER github_schedule_registry_revisions_reject_truncate
BEFORE TRUNCATE ON github_schedule_registry_revisions
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_schedule_evidence_truncate();

CREATE TRIGGER github_schedule_discovery_claims_reject_truncate
BEFORE TRUNCATE ON github_schedule_discovery_claims
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_schedule_evidence_truncate();

CREATE TRIGGER github_schedule_registry_entries_reject_truncate
BEFORE TRUNCATE ON github_schedule_registry_entries
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_schedule_evidence_truncate();

CREATE TRIGGER github_schedule_registry_seals_reject_truncate
BEFORE TRUNCATE ON github_schedule_registry_seals
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_schedule_evidence_truncate();

CREATE TRIGGER github_schedule_fires_reject_truncate
BEFORE TRUNCATE ON github_schedule_fires
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_schedule_evidence_truncate();

CREATE TRIGGER github_schedule_fire_attempts_reject_truncate
BEFORE TRUNCATE ON github_schedule_fire_attempts
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_schedule_evidence_truncate();

CREATE TRIGGER github_schedule_check_evidence_reject_truncate
BEFORE TRUNCATE ON github_schedule_check_evidence
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_schedule_evidence_truncate();

CREATE TRIGGER github_schedule_workflow_run_subject_evidence_reject_truncate
BEFORE TRUNCATE ON github_schedule_workflow_run_subject_evidence
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_schedule_evidence_truncate();
