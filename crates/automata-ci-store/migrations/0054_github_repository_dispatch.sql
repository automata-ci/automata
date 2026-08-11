ALTER TABLE github_provider_delivery_evidence
    ADD COLUMN authenticated_event_source_revision BYTEA,
    ADD COLUMN authenticated_event_source_authority TEXT COLLATE "C";

ALTER TABLE github_provider_delivery_evidence
    DROP CONSTRAINT github_provider_delivery_evidence_authenticated_event_v1,
    ADD CONSTRAINT github_provider_delivery_evidence_authenticated_event_v1 CHECK (
        (
            authenticated_event_envelope_version IS NULL
            AND authenticated_event_name IS NULL
            AND authenticated_event_git_ref IS NULL
            AND authenticated_event_source_revision IS NULL
            AND authenticated_event_source_authority IS NULL
        ) OR (
            authenticated_event_envelope_version = 1
            AND authenticated_event_name IN ('push', 'pull_request', 'merge_group')
            AND octet_length(authenticated_event_git_ref) BETWEEN 6 AND 1024
            AND authenticated_event_git_ref LIKE 'refs/%'
            AND authenticated_event_git_ref !~ '[[:cntrl:]]'
            AND authenticated_event_source_revision IS NULL
            AND authenticated_event_source_authority IS NULL
        ) OR (
            authenticated_event_envelope_version = 1
            AND authenticated_event_name = 'repository_dispatch'
            AND octet_length(authenticated_event_git_ref) BETWEEN 12 AND 1024
            AND authenticated_event_git_ref LIKE 'refs/heads/%'
            AND authenticated_event_git_ref !~ '[[:cntrl:]]'
            AND octet_length(authenticated_event_source_revision) = 20
            AND authenticated_event_source_revision <>
                pg_catalog.decode(repeat('00', 20), 'hex')
            AND (
                repository_visibility = 'public'
                AND authenticated_event_source_authority = 'public_anonymous'
                OR repository_visibility = 'private'
                AND authenticated_event_source_authority = 'private_source_authority'
            )
        )
    );

CREATE TABLE github_repository_dispatch_pending_evidence (
    provider_delivery_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    github_repository_owner_id BIGINT NOT NULL,
    provider_manifest_revision BIGINT NOT NULL,
    provider_manifest_digest BYTEA NOT NULL,
    authenticated_webhook_verifier_fingerprint_sha256 BYTEA NOT NULL,
    authenticated_webhook_verifier_revision BIGINT NOT NULL,
    authenticated_event_envelope_version SMALLINT NOT NULL,
    authenticated_event_name TEXT COLLATE "C" NOT NULL,
    authenticated_event_git_ref TEXT COLLATE "C" NOT NULL,
    checks_authority_id UUID NOT NULL,
    checks_authority_identity_digest BYTEA NOT NULL,
    checks_authority_app_configuration_revision BIGINT NOT NULL,
    checks_authority_policy_revision BIGINT NOT NULL,
    private_source_authority_id UUID,
    private_source_authority_identity_digest BYTEA,
    private_source_authority_app_configuration_revision BIGINT,
    private_source_authority_policy_revision BIGINT,

    CONSTRAINT github_repository_dispatch_pending_tenant_delivery_unique
        UNIQUE (tenant_id, provider_delivery_id),
    CONSTRAINT github_repository_dispatch_pending_inbox
        FOREIGN KEY (provider_delivery_id, tenant_id)
        REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT github_repository_dispatch_pending_manifest
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            provider_manifest_revision,
            provider_manifest_digest
        ) REFERENCES github_provider_manifest_revisions(
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        ) MATCH FULL ON DELETE RESTRICT,
    CONSTRAINT github_repository_dispatch_pending_checks_authority
        FOREIGN KEY (tenant_id, checks_authority_id)
        REFERENCES github_server_service_authorities(tenant_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT github_repository_dispatch_pending_private_authority
        FOREIGN KEY (private_source_authority_id)
        REFERENCES github_server_service_authorities(id) ON DELETE RESTRICT,
    CONSTRAINT github_repository_dispatch_pending_shape CHECK (
        provider_delivery_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND provider_connection_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND github_repository_owner_id > 0
        AND provider_manifest_revision > 0
        AND authenticated_webhook_verifier_revision > 0
        AND octet_length(provider_manifest_digest) = 32
        AND octet_length(authenticated_webhook_verifier_fingerprint_sha256) = 32
        AND authenticated_event_envelope_version = 1
        AND authenticated_event_name = 'repository_dispatch'
        AND octet_length(authenticated_event_git_ref) BETWEEN 12 AND 1024
        AND authenticated_event_git_ref LIKE 'refs/heads/%'
        AND authenticated_event_git_ref !~ '[[:cntrl:]]'
        AND checks_authority_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND octet_length(checks_authority_identity_digest) = 32
        AND checks_authority_app_configuration_revision > 0
        AND checks_authority_policy_revision > 0
        AND (
            private_source_authority_id IS NULL
            AND private_source_authority_identity_digest IS NULL
            AND private_source_authority_app_configuration_revision IS NULL
            AND private_source_authority_policy_revision IS NULL
            OR private_source_authority_id IS NOT NULL
            AND private_source_authority_id <>
                '00000000-0000-0000-0000-000000000000'::UUID
            AND private_source_authority_id <> checks_authority_id
            AND octet_length(private_source_authority_identity_digest) = 32
            AND private_source_authority_identity_digest <>
                checks_authority_identity_digest
            AND private_source_authority_app_configuration_revision > 0
            AND private_source_authority_policy_revision > 0
        )
    )
);

CREATE FUNCTION automata_github_repository_dispatch_pending_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM provider_delivery_inbox AS inbox
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = NEW.tenant_id
         AND manifest.repository_id = NEW.repository_id
         AND manifest.provider_connection_id = NEW.provider_connection_id
         AND manifest.manifest_revision = NEW.provider_manifest_revision
         AND manifest.manifest_digest = NEW.provider_manifest_digest
        JOIN github_provider_manifest_current AS current_manifest
          ON current_manifest.tenant_id = manifest.tenant_id
         AND current_manifest.repository_id = manifest.repository_id
         AND current_manifest.provider_connection_id = manifest.provider_connection_id
         AND current_manifest.manifest_revision = manifest.manifest_revision
         AND current_manifest.manifest_digest = manifest.manifest_digest
        JOIN repositories AS repository
          ON repository.tenant_id = manifest.tenant_id
         AND repository.id = manifest.repository_id
        JOIN github_server_service_authorities AS checks
          ON checks.tenant_id = NEW.tenant_id
         AND checks.id = NEW.checks_authority_id
        LEFT JOIN github_server_service_authorities AS private_source
          ON private_source.tenant_id = NEW.tenant_id
         AND private_source.id = NEW.private_source_authority_id
        WHERE inbox.id = NEW.provider_delivery_id
          AND inbox.tenant_id = NEW.tenant_id
          AND inbox.provider = 'github'
          AND inbox.raw_event_media_type =
              'application/vnd.automata.github-authenticated-event.v1+json'
          AND inbox.connection_id = manifest.provider_connection_id
          AND inbox.installation_id = manifest.provider_installation_id
          AND inbox.provider_repository_id = manifest.github_repository_id
          AND inbox.repository_identity = manifest.github_repository_name
          AND inbox.repository_visibility = manifest.repository_visibility
          AND inbox.accepted_at_ms >= current_manifest.activated_at_ms
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id = manifest.github_repository_id::TEXT
          AND repository.owner = split_part(manifest.github_repository_name, '/', 1)
          AND repository.name = split_part(manifest.github_repository_name, '/', 2)
          AND manifest.webhook_verifier_fingerprint_sha256 =
              NEW.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              NEW.authenticated_webhook_verifier_revision
          AND checks.repository_id = NEW.repository_id
          AND checks.provider_connection_id = manifest.provider_connection_id
          AND checks.provider_installation_id = manifest.provider_installation_id
          AND checks.github_app_id = manifest.github_app_id
          AND checks.github_repository_id = manifest.github_repository_id
          AND checks.github_repository_name = manifest.github_repository_name
          AND checks.service_scope = 'checks_write'
          AND checks.identity_digest = NEW.checks_authority_identity_digest
          AND checks.app_configuration_revision =
              NEW.checks_authority_app_configuration_revision
          AND checks.app_configuration_revision = manifest.app_configuration_revision
          AND checks.policy_revision = NEW.checks_authority_policy_revision
          AND checks.policy_revision = manifest.policy_revision
          AND checks.state = 'active'
          AND checks.created_at_ms <= inbox.accepted_at_ms
          AND (
              manifest.repository_visibility = 'public'
              AND NEW.private_source_authority_id IS NULL
              OR manifest.repository_visibility = 'private'
              AND private_source.id = NEW.private_source_authority_id
              AND private_source.repository_id = NEW.repository_id
              AND private_source.provider_connection_id = manifest.provider_connection_id
              AND private_source.provider_installation_id = manifest.provider_installation_id
              AND private_source.github_app_id = manifest.github_app_id
              AND private_source.github_repository_id = manifest.github_repository_id
              AND private_source.github_repository_name = manifest.github_repository_name
              AND private_source.service_scope = 'private_repository_source_read'
              AND private_source.identity_digest =
                  NEW.private_source_authority_identity_digest
              AND private_source.app_configuration_revision =
                  NEW.private_source_authority_app_configuration_revision
              AND private_source.app_configuration_revision =
                  manifest.app_configuration_revision
              AND private_source.policy_revision =
                  NEW.private_source_authority_policy_revision
              AND private_source.policy_revision = manifest.policy_revision
              AND private_source.state = 'active'
              AND private_source.created_at_ms <= inbox.accepted_at_ms
          )
    ) THEN
        RAISE EXCEPTION 'repository dispatch does not match current provider authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_repository_dispatch_pending_authority_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_repository_dispatch_pending_00_insert_guard
BEFORE INSERT ON github_repository_dispatch_pending_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_github_repository_dispatch_pending_insert_guard();

CREATE FUNCTION automata_github_repository_dispatch_pending_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'pending repository-dispatch evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_repository_dispatch_pending_immutable';
END;
$automata$;

CREATE TRIGGER github_repository_dispatch_pending_no_update_delete
BEFORE UPDATE OR DELETE ON github_repository_dispatch_pending_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_github_repository_dispatch_pending_immutable();

CREATE TRIGGER github_repository_dispatch_pending_no_truncate
BEFORE TRUNCATE ON github_repository_dispatch_pending_evidence
FOR EACH STATEMENT
EXECUTE FUNCTION automata_github_repository_dispatch_pending_immutable();

DO $automata_upgrade$
DECLARE
    current_definition TEXT;
    upgraded_definition TEXT;
    insertion TEXT := $insertion$
    IF NEW.authenticated_event_name = 'repository_dispatch' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM github_repository_dispatch_pending_evidence AS pending
            JOIN github_provider_manifest_revisions AS manifest
              ON manifest.tenant_id = pending.tenant_id
             AND manifest.repository_id = pending.repository_id
             AND manifest.provider_connection_id = pending.provider_connection_id
             AND manifest.manifest_revision = pending.provider_manifest_revision
             AND manifest.manifest_digest = pending.provider_manifest_digest
            WHERE pending.provider_delivery_id = NEW.provider_delivery_id
              AND pending.tenant_id = NEW.tenant_id
              AND pending.repository_id = NEW.repository_id
              AND pending.provider_connection_id = NEW.provider_connection_id
              AND manifest.provider_installation_id = NEW.provider_installation_id
              AND manifest.github_repository_id = NEW.github_repository_id
              AND manifest.github_repository_name = NEW.github_repository_name
              AND manifest.repository_visibility = NEW.repository_visibility
              AND pending.github_repository_owner_id = NEW.github_repository_owner_id
              AND pending.provider_manifest_revision = NEW.provider_manifest_revision
              AND pending.provider_manifest_digest = NEW.provider_manifest_digest
              AND pending.authenticated_webhook_verifier_fingerprint_sha256 =
                  NEW.authenticated_webhook_verifier_fingerprint_sha256
              AND pending.authenticated_webhook_verifier_revision =
                  NEW.authenticated_webhook_verifier_revision
              AND pending.authenticated_event_envelope_version =
                  NEW.authenticated_event_envelope_version
              AND pending.authenticated_event_name = NEW.authenticated_event_name
              AND pending.authenticated_event_git_ref = NEW.authenticated_event_git_ref
              AND pending.checks_authority_id = NEW.checks_authority_id
              AND pending.checks_authority_identity_digest =
                  NEW.checks_authority_identity_digest
              AND pending.checks_authority_app_configuration_revision =
                  NEW.checks_authority_app_configuration_revision
              AND pending.checks_authority_policy_revision =
                  NEW.checks_authority_policy_revision
              AND pending.private_source_authority_id IS NOT DISTINCT FROM
                  NEW.private_source_authority_id
              AND pending.private_source_authority_identity_digest IS NOT DISTINCT FROM
                  NEW.private_source_authority_identity_digest
              AND pending.private_source_authority_app_configuration_revision IS NOT DISTINCT FROM
                  NEW.private_source_authority_app_configuration_revision
              AND pending.private_source_authority_policy_revision IS NOT DISTINCT FROM
                  NEW.private_source_authority_policy_revision
        ) THEN
            RAISE EXCEPTION 'resolved repository dispatch does not match pending authority'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_repository_dispatch_resolution_exact';
        END IF;
        RETURN NEW;
    END IF;

$insertion$;
BEGIN
    SELECT pg_get_functiondef(
        'automata_github_provider_delivery_evidence_insert_guard()'::REGPROCEDURE
    ) INTO current_definition;
    IF strpos(current_definition, 'BEGIN' || chr(10) || '    SELECT * INTO inbox') = 0 THEN
        RAISE EXCEPTION 'provider delivery evidence guard has unexpected shape'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    upgraded_definition := replace(
        current_definition,
        'BEGIN' || chr(10) || '    SELECT * INTO inbox',
        'BEGIN' || chr(10) || insertion || '    SELECT * INTO inbox'
    );
    EXECUTE upgraded_definition;
END;
$automata_upgrade$;

CREATE OR REPLACE FUNCTION automata_github_delivery_requires_atomic_queued_check()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    evidence github_provider_delivery_evidence%ROWTYPE;
    pending github_repository_dispatch_pending_evidence%ROWTYPE;
    manifest github_provider_manifest_revisions%ROWTYPE;
    subject github_check_subjects%ROWTYPE;
    outbox github_check_projection_outbox%ROWTYPE;
BEGIN
    IF NEW.provider <> 'github' THEN
        RETURN NULL;
    END IF;

    SELECT * INTO evidence
    FROM github_provider_delivery_evidence
    WHERE provider_delivery_id = NEW.id
      AND tenant_id = NEW.tenant_id;

    IF evidence.provider_delivery_id IS NULL THEN
        SELECT * INTO pending
        FROM github_repository_dispatch_pending_evidence
        WHERE provider_delivery_id = NEW.id
          AND tenant_id = NEW.tenant_id;
        IF pending.provider_delivery_id IS NOT NULL
            AND pending.authenticated_event_envelope_version = 1
            AND pending.authenticated_event_name = 'repository_dispatch'
            AND NEW.raw_event_media_type =
                'application/vnd.automata.github-authenticated-event.v1+json'
        THEN
            RETURN NULL;
        END IF;
    END IF;

    IF evidence.provider_delivery_id IS NOT NULL THEN
        SELECT * INTO manifest
        FROM github_provider_manifest_revisions
        WHERE tenant_id = evidence.tenant_id
          AND repository_id = evidence.repository_id
          AND provider_connection_id = evidence.provider_connection_id
          AND manifest_revision = evidence.provider_manifest_revision
          AND manifest_digest = evidence.provider_manifest_digest;

        SELECT * INTO subject
        FROM github_check_subjects
        WHERE id = evidence.github_check_subject_id
          AND provider_delivery_id = NEW.id
          AND tenant_id = NEW.tenant_id
          AND subject_key = manifest.check_subject_key;

        IF subject.id IS NOT NULL THEN
            SELECT * INTO outbox
            FROM github_check_projection_outbox
            WHERE subject_id = subject.id;
        END IF;
    END IF;

    IF evidence.provider_delivery_id IS NULL
        OR manifest.provider_connection_id IS NULL
        OR subject.id IS NULL
        OR subject.head_sha <> evidence.github_check_head_sha
        OR subject.workflow_run_id IS NOT NULL
        OR subject.linked_at_ms IS NOT NULL
        OR subject.desired_state <> 'queued'
        OR subject.desired_conclusion IS NOT NULL
        OR subject.terminal_cause IS NOT NULL
        OR subject.desired_revision <> 1
        OR subject.created_at_ms <> NEW.accepted_at_ms
        OR subject.desired_updated_at_ms <> NEW.accepted_at_ms
        OR outbox.subject_id IS NULL
        OR outbox.state <> 'pending'
        OR outbox.attempted_revision IS NOT NULL
        OR outbox.attempt_count <> 0
        OR outbox.claim_fence <> 0
        OR outbox.projected_revision <> 0
        OR outbox.state_updated_at_ms <> NEW.accepted_at_ms
    THEN
        RAISE EXCEPTION 'GitHub delivery requires pinned pending dispatch or one queued Check'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_delivery_atomic_evidence_required';
    END IF;

    RETURN NULL;
END;
$automata$;
