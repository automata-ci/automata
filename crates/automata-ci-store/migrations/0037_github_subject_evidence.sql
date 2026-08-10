-- Current-only signed GitHub repository-owner and workflow-subject evidence.
--
-- A generic provider inbox remains provider-neutral. GitHub ingress commits a
-- one-to-one immutable extension, its exact queued Check/outbox, the complete
-- historical provider-manifest pin, and the required server-service authority
-- selectors in one transaction. Logical admission later links that Check to
-- one exact run and commits the immutable run subject receipt in the same
-- transaction as the run. No provider/name fallback or pre-release backfill is
-- possible.

LOCK TABLE provider_delivery_inbox IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE github_check_subjects IN SHARE ROW EXCLUSIVE MODE;

-- 0035 already refused this pre-release state. Repeat the audit while holding
-- both writer-conflicting locks so applying 0037 directly or racing a writer
-- can never guess an owner identity, authority selector, or manifest revision.
DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1 FROM provider_delivery_inbox WHERE provider = 'github'
    ) OR EXISTS (
        SELECT 1 FROM github_check_subjects
    ) THEN
        RAISE EXCEPTION 'pre-evidence GitHub deliveries and Check subjects must be explicitly drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_subject_evidence_current_only';
    END IF;
END;
$automata$;

-- Only the provider-authenticated logical-admission transaction sets this at
-- receipt creation. Generic/local admissions retain FALSE and are permanently
-- ineligible for GitHub subject-evidence insertion or backfill.
ALTER TABLE workflow_admission_receipts
    ADD COLUMN github_subject_evidence_required BOOLEAN NOT NULL DEFAULT FALSE;

CREATE FUNCTION automata_workflow_admission_github_evidence_flag_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.github_subject_evidence_required IS DISTINCT FROM
        OLD.github_subject_evidence_required
    THEN
        RAISE EXCEPTION 'workflow admission GitHub evidence expectation is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_admission_github_evidence_flag_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_admission_github_evidence_flag_immutable
BEFORE UPDATE ON workflow_admission_receipts
FOR EACH ROW
EXECUTE FUNCTION automata_workflow_admission_github_evidence_flag_immutable();

CREATE TABLE github_provider_delivery_evidence (
    provider_delivery_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    provider_installation_id BIGINT NOT NULL,
    github_repository_id BIGINT NOT NULL,
    github_repository_owner_id BIGINT NOT NULL,
    github_repository_name TEXT COLLATE "C" NOT NULL,
    repository_visibility TEXT COLLATE "C" NOT NULL,
    provider_manifest_revision BIGINT NOT NULL,
    provider_manifest_digest BYTEA NOT NULL,
    authenticated_webhook_verifier_fingerprint_sha256 BYTEA NOT NULL,
    authenticated_webhook_verifier_revision BIGINT NOT NULL,
    checks_authority_id UUID NOT NULL,
    checks_authority_identity_digest BYTEA NOT NULL,
    checks_authority_app_configuration_revision BIGINT NOT NULL,
    checks_authority_policy_revision BIGINT NOT NULL,
    private_source_authority_id UUID,
    private_source_authority_identity_digest BYTEA,
    private_source_authority_app_configuration_revision BIGINT,
    private_source_authority_policy_revision BIGINT,
    github_check_subject_id UUID NOT NULL,
    github_check_head_sha BYTEA NOT NULL,

    CONSTRAINT github_provider_delivery_evidence_tenant_repository_delivery_unique
        UNIQUE (tenant_id, repository_id, provider_delivery_id),
    CONSTRAINT github_provider_delivery_evidence_tenant_check_unique
        UNIQUE (tenant_id, github_check_subject_id),
    CONSTRAINT github_provider_delivery_evidence_inbox
        FOREIGN KEY (provider_delivery_id, tenant_id)
        REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT github_provider_delivery_evidence_manifest
        FOREIGN KEY (
            tenant_id, repository_id, provider_connection_id,
            provider_manifest_revision, provider_manifest_digest
        ) REFERENCES github_provider_manifest_revisions(
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest
        ) MATCH FULL ON DELETE RESTRICT,
    CONSTRAINT github_provider_delivery_evidence_checks_authority
        FOREIGN KEY (tenant_id, checks_authority_id)
        REFERENCES github_server_service_authorities(tenant_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT github_provider_delivery_evidence_private_source_authority
        FOREIGN KEY (private_source_authority_id)
        REFERENCES github_server_service_authorities(id) ON DELETE RESTRICT,
    CONSTRAINT github_provider_delivery_evidence_check_subject
        FOREIGN KEY (tenant_id, github_check_subject_id)
        REFERENCES github_check_subjects(tenant_id, id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT github_provider_delivery_evidence_non_nil CHECK (
        provider_delivery_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND provider_connection_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND checks_authority_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND github_check_subject_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND (
            private_source_authority_id IS NULL
            OR private_source_authority_id <>
                '00000000-0000-0000-0000-000000000000'::UUID
        )
    ),
    CONSTRAINT github_provider_delivery_evidence_positive CHECK (
        provider_installation_id > 0
        AND github_repository_id > 0
        AND github_repository_owner_id > 0
        AND provider_manifest_revision > 0
        AND authenticated_webhook_verifier_revision > 0
        AND checks_authority_app_configuration_revision > 0
        AND checks_authority_policy_revision > 0
        AND (
            private_source_authority_id IS NULL
            OR private_source_authority_app_configuration_revision > 0
                AND private_source_authority_policy_revision > 0
        )
    ),
    CONSTRAINT github_provider_delivery_evidence_digest_shape CHECK (
        octet_length(provider_manifest_digest) = 32
        AND octet_length(authenticated_webhook_verifier_fingerprint_sha256) = 32
        AND authenticated_webhook_verifier_fingerprint_sha256 <>
            pg_catalog.decode(repeat('00', 32), 'hex')
        AND octet_length(checks_authority_identity_digest) = 32
        AND (
            private_source_authority_identity_digest IS NULL
            OR octet_length(private_source_authority_identity_digest) = 32
        )
        AND octet_length(github_check_head_sha) = 20
        AND github_check_head_sha <> pg_catalog.decode(repeat('00', 20), 'hex')
    ),
    CONSTRAINT github_provider_delivery_evidence_private_selector_shape CHECK (
        (
            repository_visibility = 'public'
            AND private_source_authority_id IS NULL
            AND private_source_authority_identity_digest IS NULL
            AND private_source_authority_app_configuration_revision IS NULL
            AND private_source_authority_policy_revision IS NULL
        ) OR (
            repository_visibility = 'private'
            AND private_source_authority_id IS NOT NULL
            AND private_source_authority_identity_digest IS NOT NULL
            AND private_source_authority_app_configuration_revision IS NOT NULL
            AND private_source_authority_policy_revision IS NOT NULL
            AND private_source_authority_id <> checks_authority_id
            AND private_source_authority_identity_digest <>
                checks_authority_identity_digest
        )
    ),
    CONSTRAINT github_provider_delivery_evidence_repository_name CHECK (
        array_length(string_to_array(github_repository_name, '/'), 1) = 2
        AND octet_length(split_part(github_repository_name, '/', 1)) BETWEEN 1 AND 39
        AND split_part(github_repository_name, '/', 1)
            ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$'
        AND split_part(github_repository_name, '/', 1) !~ '--'
        AND octet_length(split_part(github_repository_name, '/', 2)) BETWEEN 1 AND 100
        AND split_part(github_repository_name, '/', 2) ~ '^[A-Za-z0-9._-]+$'
        AND split_part(github_repository_name, '/', 2) NOT IN ('.', '..')
        AND split_part(github_repository_name, '/', 2) !~* '[.]git$'
    ),
    CONSTRAINT github_provider_delivery_evidence_visibility CHECK (
        repository_visibility IN ('public', 'private')
    )
);

CREATE FUNCTION automata_github_provider_delivery_evidence_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    inbox provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    manifest_pin RECORD;
    checks_authority github_server_service_authorities%ROWTYPE;
    private_authority github_server_service_authorities%ROWTYPE;
BEGIN
    SELECT * INTO inbox
    FROM provider_delivery_inbox
    WHERE id = NEW.provider_delivery_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;

    SELECT * INTO repository
    FROM repositories
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.repository_id
    FOR SHARE;

    SELECT manifest_source.*,
           current_source.activated_at_ms AS current_activated_at_ms
      INTO manifest_pin
    FROM github_provider_manifest_revisions AS manifest_source
    JOIN github_provider_manifest_current AS current_source
      ON current_source.tenant_id = manifest_source.tenant_id
     AND current_source.repository_id = manifest_source.repository_id
     AND current_source.provider_connection_id = manifest_source.provider_connection_id
     AND current_source.manifest_revision = manifest_source.manifest_revision
     AND current_source.manifest_digest = manifest_source.manifest_digest
    WHERE manifest_source.tenant_id = NEW.tenant_id
      AND manifest_source.repository_id = NEW.repository_id
      AND manifest_source.provider_connection_id = NEW.provider_connection_id
      AND manifest_source.manifest_revision = NEW.provider_manifest_revision
      AND manifest_source.manifest_digest = NEW.provider_manifest_digest
    FOR SHARE OF manifest_source, current_source;

    SELECT * INTO checks_authority
    FROM github_server_service_authorities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.checks_authority_id
    FOR SHARE;

    IF NEW.private_source_authority_id IS NOT NULL THEN
        SELECT * INTO private_authority
        FROM github_server_service_authorities
        WHERE tenant_id = NEW.tenant_id
          AND id = NEW.private_source_authority_id
        FOR SHARE;
    END IF;

    IF inbox.id IS NULL
        OR repository.id IS NULL
        OR manifest_pin.provider_connection_id IS NULL
        OR checks_authority.id IS NULL
        OR inbox.provider <> 'github'
        OR inbox.connection_id <> NEW.provider_connection_id
        OR inbox.installation_id <> NEW.provider_installation_id
        OR inbox.provider_repository_id <> NEW.github_repository_id
        OR inbox.repository_identity <> NEW.github_repository_name
        OR inbox.repository_visibility <> NEW.repository_visibility
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner <> split_part(NEW.github_repository_name, '/', 1)
        OR repository.name <> split_part(NEW.github_repository_name, '/', 2)
        OR manifest_pin.provider_installation_id <> NEW.provider_installation_id
        OR manifest_pin.github_repository_id <> NEW.github_repository_id
        OR manifest_pin.github_repository_name <> NEW.github_repository_name
        OR manifest_pin.repository_visibility <> NEW.repository_visibility
        OR manifest_pin.webhook_verifier_fingerprint_sha256 <>
            NEW.authenticated_webhook_verifier_fingerprint_sha256
        OR manifest_pin.webhook_verifier_revision <>
            NEW.authenticated_webhook_verifier_revision
        OR inbox.accepted_at_ms < manifest_pin.current_activated_at_ms
        OR checks_authority.repository_id <> NEW.repository_id
        OR checks_authority.provider_connection_id <> NEW.provider_connection_id
        OR checks_authority.provider_installation_id <> NEW.provider_installation_id
        OR checks_authority.github_app_id <> manifest_pin.github_app_id
        OR checks_authority.github_repository_id <> NEW.github_repository_id
        OR checks_authority.github_repository_name <> NEW.github_repository_name
        OR checks_authority.service_scope <> 'checks_write'
        OR checks_authority.github_app_client_id <> manifest_pin.github_app_client_id
        OR checks_authority.github_app_jwt_issuer_kind <>
            manifest_pin.github_app_jwt_issuer_kind
        OR checks_authority.app_key_spki_sha256 <> manifest_pin.app_key_spki_sha256
        OR checks_authority.app_configuration_revision <>
            NEW.checks_authority_app_configuration_revision
        OR checks_authority.app_configuration_revision <>
            manifest_pin.app_configuration_revision
        OR checks_authority.policy_revision <> NEW.checks_authority_policy_revision
        OR checks_authority.policy_revision <> manifest_pin.policy_revision
        OR checks_authority.identity_digest <> NEW.checks_authority_identity_digest
        OR checks_authority.state <> 'active'
        OR checks_authority.created_at_ms > inbox.accepted_at_ms
        OR (
            NEW.repository_visibility = 'public'
            AND NEW.private_source_authority_id IS NOT NULL
        )
        OR (
            NEW.repository_visibility = 'private'
            AND (
                private_authority.id IS NULL
                OR private_authority.repository_id <> NEW.repository_id
                OR private_authority.provider_connection_id <> NEW.provider_connection_id
                OR private_authority.provider_installation_id <>
                    NEW.provider_installation_id
                OR private_authority.github_app_id <> manifest_pin.github_app_id
                OR private_authority.github_repository_id <> NEW.github_repository_id
                OR private_authority.github_repository_name <> NEW.github_repository_name
                OR private_authority.service_scope <>
                    'private_repository_source_read'
                OR private_authority.github_app_client_id <>
                    manifest_pin.github_app_client_id
                OR private_authority.github_app_jwt_issuer_kind <>
                    manifest_pin.github_app_jwt_issuer_kind
                OR private_authority.app_key_spki_sha256 <>
                    manifest_pin.app_key_spki_sha256
                OR private_authority.app_configuration_revision <>
                    NEW.private_source_authority_app_configuration_revision
                OR private_authority.app_configuration_revision <>
                    manifest_pin.app_configuration_revision
                OR private_authority.policy_revision <>
                    NEW.private_source_authority_policy_revision
                OR private_authority.policy_revision <> manifest_pin.policy_revision
                OR private_authority.identity_digest <>
                    NEW.private_source_authority_identity_digest
                OR private_authority.state <> 'active'
                OR private_authority.created_at_ms > inbox.accepted_at_ms
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub delivery evidence is not the exact current manifest and service authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_provider_delivery_evidence_authority_exact';
    END IF;

    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_provider_delivery_evidence_00_insert_guard
BEFORE INSERT ON github_provider_delivery_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_delivery_evidence_insert_guard();

CREATE FUNCTION automata_github_provider_delivery_evidence_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub provider delivery evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_provider_delivery_evidence_immutable';
END;
$automata$;

CREATE TRIGGER github_provider_delivery_evidence_no_update_delete
BEFORE UPDATE OR DELETE ON github_provider_delivery_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_github_provider_delivery_evidence_immutable();

CREATE TRIGGER github_provider_delivery_evidence_no_truncate
BEFORE TRUNCATE ON github_provider_delivery_evidence
FOR EACH STATEMENT
EXECUTE FUNCTION automata_github_provider_delivery_evidence_immutable();

-- A Check pin is transitive through its immutable delivery evidence. The
-- signed head and generated subject ID are retained independently in the
-- extension so a different Check cannot be substituted before admission.
CREATE FUNCTION automata_github_check_subject_delivery_evidence_exact()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    authority RECORD;
BEGIN
    SELECT evidence_source.repository_id,
           evidence_source.provider_connection_id,
           evidence_source.provider_installation_id,
           evidence_source.github_repository_id,
           evidence_source.github_repository_name,
           evidence_source.github_check_subject_id,
           evidence_source.github_check_head_sha,
           inbox_source.accepted_at_ms,
           manifest_source.check_subject_key,
           manifest_source.github_app_id,
           manifest_source.check_name
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

    IF NOT FOUND
        OR NEW.id <> authority.github_check_subject_id
        OR NEW.repository_id <> authority.repository_id
        OR NEW.provider_connection_id <> authority.provider_connection_id
        OR NEW.provider_installation_id <> authority.provider_installation_id
        OR NEW.github_repository_id <> authority.github_repository_id
        OR NEW.github_repository_name <> authority.github_repository_name
        OR NEW.subject_key <> authority.check_subject_key
        OR NEW.github_app_id <> authority.github_app_id
        OR NEW.head_sha <> authority.github_check_head_sha
        OR NEW.check_name <> authority.check_name
        OR NEW.created_at_ms <> authority.accepted_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check subject does not match its signed delivery evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_delivery_evidence_exact';
    END IF;

    RETURN NEW;
END;
$automata$;

-- The existing 0032 canonical-name derivation sorts first and populates the
-- exact name before this manifest/evidence comparison runs.
CREATE TRIGGER github_check_subjects_00_delivery_evidence_exact
BEFORE INSERT ON github_check_subjects
FOR EACH ROW
EXECUTE FUNCTION automata_github_check_subject_delivery_evidence_exact();

-- A GitHub inbox insert may commit only together with its exact queued Check
-- subject and trigger-created pending outbox row. Deferral permits inbox ->
-- evidence -> subject order while making a bare pinned inbox impossible.
CREATE FUNCTION automata_github_delivery_requires_atomic_queued_check()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    evidence github_provider_delivery_evidence%ROWTYPE;
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
        RAISE EXCEPTION 'GitHub delivery requires one atomic manifest-pinned queued Check subject'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_delivery_atomic_queued_check_required';
    END IF;

    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER provider_delivery_inbox_require_atomic_github_check
AFTER INSERT ON provider_delivery_inbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_github_delivery_requires_atomic_queued_check();

-- Both 0035 interim guards are replaced inside this migration transaction,
-- only after the exact extension/Check/authority and deferred atomicity proofs
-- exist. Dropping either guard in isolation is forbidden by design.
DROP TRIGGER provider_delivery_inbox_00_require_github_manifest_pin
    ON provider_delivery_inbox;
DROP TRIGGER github_check_subjects_00_00_require_manifest_pin
    ON github_check_subjects;
DROP FUNCTION automata_github_provider_manifest_reject_unpinned_delivery();
DROP FUNCTION automata_github_provider_manifest_reject_unpinned_check();

CREATE FUNCTION automata_github_workflow_run_subject_evidence_digest(
    tenant_id TEXT,
    repository_id UUID,
    workflow_id UUID,
    snapshot_id UUID,
    run_id UUID,
    root_invocation_id UUID,
    provider_delivery_id UUID,
    provider_delivery_idempotency_key TEXT,
    admission_claim_owner_id UUID,
    admission_claim_attempt SMALLINT,
    admission_claim_fence BIGINT,
    admission_claimed_at_ms BIGINT,
    admission_claim_expires_at_ms BIGINT,
    github_check_subject_id UUID,
    github_check_head_sha BYTEA,
    provider_connection_id UUID,
    provider_installation_id BIGINT,
    github_repository_id BIGINT,
    github_repository_owner_id BIGINT,
    github_repository_name TEXT,
    repository_visibility TEXT,
    provider_manifest_revision BIGINT,
    provider_manifest_digest BYTEA,
    authenticated_webhook_verifier_fingerprint_sha256 BYTEA,
    authenticated_webhook_verifier_revision BIGINT,
    checks_authority_id UUID,
    checks_authority_identity_digest BYTEA,
    checks_authority_app_configuration_revision BIGINT,
    checks_authority_policy_revision BIGINT,
    private_source_authority_id UUID,
    private_source_authority_identity_digest BYTEA,
    private_source_authority_app_configuration_revision BIGINT,
    private_source_authority_policy_revision BIGINT,
    request_digest BYTEA,
    raw_event_digest BYTEA,
    accepted_at_ms BIGINT,
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
        'automata.store.github-workflow-run-subject-evidence.v1', 'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(tenant_id, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(repository_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(workflow_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(snapshot_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(run_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(root_invocation_id))
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(provider_delivery_id))
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(provider_delivery_idempotency_key, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.uuid_send(admission_claim_owner_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(admission_claim_attempt::BIGINT)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(admission_claim_fence)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(admission_claimed_at_ms)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(admission_claim_expires_at_ms)
    )
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(github_check_subject_id))
    || automata_github_provider_manifest_digest_part(github_check_head_sha)
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(provider_connection_id))
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(provider_installation_id)
    )
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(github_repository_id))
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(github_repository_owner_id)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(github_repository_name, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(repository_visibility, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(provider_manifest_revision)
    )
    || automata_github_provider_manifest_digest_part(provider_manifest_digest)
    || automata_github_provider_manifest_digest_part(
        authenticated_webhook_verifier_fingerprint_sha256
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(authenticated_webhook_verifier_revision)
    )
    || automata_github_provider_manifest_digest_part(pg_catalog.uuid_send(checks_authority_id))
    || automata_github_provider_manifest_digest_part(checks_authority_identity_digest)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(checks_authority_app_configuration_revision)
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(checks_authority_policy_revision)
    )
    || automata_github_provider_manifest_digest_part(
        CASE WHEN private_source_authority_id IS NULL
            THEN pg_catalog.decode('00', 'hex')
            ELSE pg_catalog.decode('01', 'hex')
        END
    )
    || CASE WHEN private_source_authority_id IS NULL THEN ''::BYTEA ELSE
        automata_github_provider_manifest_digest_part(
            pg_catalog.uuid_send(private_source_authority_id)
        )
        || automata_github_provider_manifest_digest_part(
            private_source_authority_identity_digest
        )
        || automata_github_provider_manifest_digest_part(
            pg_catalog.int8send(private_source_authority_app_configuration_revision)
        )
        || automata_github_provider_manifest_digest_part(
            pg_catalog.int8send(private_source_authority_policy_revision)
        )
       END
    || automata_github_provider_manifest_digest_part(request_digest)
    || automata_github_provider_manifest_digest_part(raw_event_digest)
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(accepted_at_ms))
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(workflow_path, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(source_digest)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(event_name, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(event_digest)
    || automata_github_provider_manifest_digest_part(
        pg_catalog.convert_to(git_ref, 'UTF8')
    )
    || automata_github_provider_manifest_digest_part(
        pg_catalog.int8send(workflow_plan_schema::BIGINT)
    )
    || automata_github_provider_manifest_digest_part(plan_digest)
    || automata_github_provider_manifest_digest_part(logical_admission_digest)
    || automata_github_provider_manifest_digest_part(pg_catalog.int8send(admitted_at_ms))
)
$automata$;

CREATE TABLE github_workflow_run_subject_evidence (
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    workflow_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,
    run_id UUID NOT NULL,
    root_invocation_id UUID NOT NULL,
    provider_delivery_id UUID NOT NULL,
    provider_delivery_idempotency_key TEXT COLLATE "C" NOT NULL,
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
    subject_evidence_sha256 BYTEA NOT NULL,
    admitted_at_ms BIGINT NOT NULL,

    CONSTRAINT github_workflow_run_subject_evidence_primary_key
        PRIMARY KEY (repository_id, run_id),
    CONSTRAINT github_workflow_run_subject_evidence_tenant_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_run_subject_evidence_repository_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_run_subject_evidence_workflow
        FOREIGN KEY (repository_id, workflow_id)
        REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_run_subject_evidence_snapshot
        FOREIGN KEY (snapshot_id, workflow_id)
        REFERENCES workflow_snapshots(id, workflow_id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_run_subject_evidence_delivery
        FOREIGN KEY (tenant_id, repository_id, provider_delivery_id)
        REFERENCES github_provider_delivery_evidence(
            tenant_id, repository_id, provider_delivery_id
        ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_run_subject_evidence_check
        FOREIGN KEY (tenant_id, github_check_subject_id)
        REFERENCES github_check_subjects(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_run_subject_evidence_non_nil CHECK (
        repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND workflow_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND snapshot_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND run_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND root_invocation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND provider_delivery_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND admission_claim_owner_id <>
            '00000000-0000-0000-0000-000000000000'::UUID
        AND github_check_subject_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT github_workflow_run_subject_evidence_digest_shape CHECK (
        octet_length(github_check_head_sha) = 20
        AND github_check_head_sha <> pg_catalog.decode(repeat('00', 20), 'hex')
        AND octet_length(source_digest) = 32
        AND octet_length(event_digest) = 32
        AND octet_length(plan_digest) = 32
        AND octet_length(logical_admission_digest) = 32
        AND octet_length(subject_evidence_sha256) = 32
    ),
    CONSTRAINT github_workflow_run_subject_evidence_selector_shape CHECK (
        octet_length(provider_delivery_idempotency_key) BETWEEN 1 AND 1024
        AND provider_delivery_idempotency_key !~ '[[:cntrl:]]'
        AND
        octet_length(workflow_path) BETWEEN 1 AND 1024
        AND btrim(workflow_path) = workflow_path
        AND workflow_path !~ '[[:cntrl:]\\]'
        AND left(workflow_path, 1) <> '/'
        AND workflow_path !~ '(^|/)(\.|\.\.)(/|$)'
        AND workflow_path !~ '//'
        AND octet_length(event_name) BETWEEN 1 AND 1024
        AND event_name !~ '[[:cntrl:]]'
        AND octet_length(git_ref) BETWEEN 6 AND 1024
        AND git_ref LIKE 'refs/%'
        AND git_ref !~ '[[:cntrl:]]'
        AND workflow_plan_schema = 2
    ),
    CONSTRAINT github_workflow_run_subject_evidence_time CHECK (
        admission_claim_attempt BETWEEN 1 AND 16
        AND admission_claim_fence > 0
        AND admission_claimed_at_ms >= 0
        AND admission_claim_expires_at_ms > admission_claimed_at_ms
        AND admission_claim_expires_at_ms - admission_claimed_at_ms <= 3600000
        AND admitted_at_ms >= admission_claimed_at_ms
        AND admitted_at_ms < admission_claim_expires_at_ms
    )
);

CREATE FUNCTION automata_github_workflow_run_subject_evidence_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    source_evidence RECORD;
    source_evidence_found BOOLEAN;
    run_evidence RECORD;
    run_evidence_found BOOLEAN;
    expected_digest BYTEA;
BEGIN
    SELECT evidence_source.*,
           inbox_source.request_digest,
           inbox_source.raw_event_digest,
           inbox_source.accepted_at_ms,
           inbox_source.state AS inbox_state,
           inbox_source.attempt_count AS inbox_attempt_count,
           inbox_source.claim_fence AS inbox_claim_fence,
           inbox_source.claim_owner_id AS inbox_claim_owner_id,
           inbox_source.claimed_at_ms AS inbox_claimed_at_ms,
           inbox_source.claim_expires_at_ms AS inbox_claim_expires_at_ms,
           manifest_source.workflow_path AS manifest_workflow_path,
           manifest_source.event_name AS manifest_event_name,
           manifest_source.git_ref AS manifest_git_ref,
           subject_source.id AS subject_id,
           subject_source.provider_delivery_id AS subject_delivery_id,
           subject_source.repository_id AS subject_repository_id,
           subject_source.head_sha AS subject_head_sha,
           subject_source.subject_key AS subject_key,
           subject_source.workflow_run_id AS subject_run_id,
           subject_source.linked_at_ms AS subject_linked_at_ms,
           subject_source.desired_state AS subject_desired_state,
           subject_source.desired_conclusion AS subject_desired_conclusion,
           subject_source.terminal_cause AS subject_terminal_cause,
           subject_source.desired_revision AS subject_desired_revision,
           subject_source.desired_updated_at_ms AS subject_desired_updated_at_ms,
           repository_source.scm_provider AS repository_scm_provider,
           repository_source.provider_repository_id AS repository_provider_id,
           repository_source.owner AS repository_owner,
           repository_source.name AS repository_name
      INTO source_evidence
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
     AND manifest_source.webhook_verifier_fingerprint_sha256 =
         evidence_source.authenticated_webhook_verifier_fingerprint_sha256
     AND manifest_source.webhook_verifier_revision =
         evidence_source.authenticated_webhook_verifier_revision
    JOIN repositories AS repository_source
      ON repository_source.tenant_id = evidence_source.tenant_id
     AND repository_source.id = evidence_source.repository_id
    JOIN github_check_subjects AS subject_source
      ON subject_source.id = evidence_source.github_check_subject_id
     AND subject_source.tenant_id = evidence_source.tenant_id
    WHERE evidence_source.provider_delivery_id = NEW.provider_delivery_id
      AND evidence_source.tenant_id = NEW.tenant_id
      AND evidence_source.repository_id = NEW.repository_id
    FOR SHARE OF evidence_source, inbox_source, manifest_source, subject_source,
                 repository_source;
    source_evidence_found = FOUND;

    SELECT run_source.repository_id,
           run_source.workflow_id,
           run_source.snapshot_id,
           run_source.head_sha,
           run_source.event_name,
           run_source.event_digest,
           run_source.git_ref,
           run_source.plan_schema,
           run_source.plan_digest,
           run_source.admission_epoch,
           run_source.created_at_ms,
           workflow_source.path AS workflow_path,
           snapshot_source.source_digest,
           marker_source.root_invocation_id,
           marker_source.admission_digest,
           marker_source.admitted_at_ms AS marker_admitted_at_ms,
           invocation_source.plan_schema AS invocation_plan_schema,
           invocation_source.plan_digest AS invocation_plan_digest,
           admission_receipt_source.repository_id AS receipt_repository_id,
           admission_receipt_source.run_id AS receipt_run_id,
           admission_receipt_source.committed_at_ms AS receipt_committed_at_ms,
           admission_receipt_source.github_subject_evidence_required AS
               receipt_github_evidence_required
      INTO run_evidence
    FROM workflow_runs AS run_source
    JOIN workflow_definitions AS workflow_source
      ON workflow_source.id = run_source.workflow_id
     AND workflow_source.repository_id = run_source.repository_id
    JOIN workflow_snapshots AS snapshot_source
      ON snapshot_source.id = run_source.snapshot_id
     AND snapshot_source.workflow_id = run_source.workflow_id
    JOIN workflow_plan_v2_runs AS marker_source
      ON marker_source.run_id = run_source.id
    JOIN workflow_plan_v2_invocations AS invocation_source
      ON invocation_source.run_id = run_source.id
     AND invocation_source.id = marker_source.root_invocation_id
    JOIN github_provider_delivery_evidence AS admission_evidence_source
      ON admission_evidence_source.tenant_id = NEW.tenant_id
     AND admission_evidence_source.repository_id = NEW.repository_id
     AND admission_evidence_source.provider_delivery_id = NEW.provider_delivery_id
    JOIN provider_delivery_inbox AS admission_inbox_source
      ON admission_inbox_source.id = admission_evidence_source.provider_delivery_id
     AND admission_inbox_source.tenant_id = admission_evidence_source.tenant_id
    JOIN workflow_admission_receipts AS admission_receipt_source
     ON admission_receipt_source.tenant_id = admission_evidence_source.tenant_id
     AND admission_receipt_source.idempotency_kind = 'provider_delivery'
     AND admission_receipt_source.idempotency_key =
         NEW.provider_delivery_idempotency_key
     AND admission_receipt_source.request_digest = marker_source.admission_digest
    WHERE run_source.repository_id = NEW.repository_id
      AND run_source.id = NEW.run_id
    FOR SHARE OF run_source, workflow_source, snapshot_source,
                 marker_source, invocation_source, admission_evidence_source,
                 admission_inbox_source, admission_receipt_source;
    run_evidence_found = FOUND;

    IF NOT source_evidence_found
        OR NOT run_evidence_found
        OR NEW.workflow_id <> run_evidence.workflow_id
        OR NEW.snapshot_id <> run_evidence.snapshot_id
        OR NEW.root_invocation_id <> run_evidence.root_invocation_id
        OR NEW.github_check_subject_id <> source_evidence.github_check_subject_id
        OR NEW.github_check_subject_id <> source_evidence.subject_id
        OR NEW.github_check_head_sha <> source_evidence.github_check_head_sha
        OR NEW.github_check_head_sha <> source_evidence.subject_head_sha
        OR NEW.github_check_head_sha <> run_evidence.head_sha
        OR source_evidence.repository_scm_provider <> 'github'
        OR source_evidence.repository_provider_id <>
            source_evidence.github_repository_id::TEXT
        OR source_evidence.repository_owner <>
            split_part(source_evidence.github_repository_name, '/', 1)
        OR source_evidence.repository_name <>
            split_part(source_evidence.github_repository_name, '/', 2)
        OR run_evidence.receipt_repository_id IS DISTINCT FROM NEW.repository_id
        OR run_evidence.receipt_run_id IS DISTINCT FROM NEW.run_id
        OR run_evidence.receipt_committed_at_ms IS DISTINCT FROM NEW.admitted_at_ms
        OR run_evidence.receipt_github_evidence_required IS DISTINCT FROM TRUE
        OR source_evidence.inbox_state <> 'claimed'
        OR source_evidence.inbox_attempt_count <> NEW.admission_claim_attempt
        OR source_evidence.inbox_claim_fence <> NEW.admission_claim_fence
        OR source_evidence.inbox_claim_owner_id <> NEW.admission_claim_owner_id
        OR source_evidence.inbox_claimed_at_ms <> NEW.admission_claimed_at_ms
        OR source_evidence.inbox_claim_expires_at_ms <>
            NEW.admission_claim_expires_at_ms
        OR NEW.admitted_at_ms < NEW.admission_claimed_at_ms
        OR NEW.admitted_at_ms >= NEW.admission_claim_expires_at_ms
        OR source_evidence.subject_delivery_id <> NEW.provider_delivery_id
        OR source_evidence.subject_repository_id <> NEW.repository_id
        OR source_evidence.subject_run_id <> NEW.run_id
        OR source_evidence.subject_linked_at_ms <> NEW.admitted_at_ms
        OR source_evidence.subject_desired_state <> 'in_progress'
        OR source_evidence.subject_desired_conclusion IS NOT NULL
        OR source_evidence.subject_terminal_cause IS NOT NULL
        OR source_evidence.subject_desired_revision <> 2
        OR source_evidence.subject_desired_updated_at_ms <> NEW.admitted_at_ms
        OR source_evidence.subject_key <> source_evidence.manifest_workflow_path
        OR NEW.workflow_path <> source_evidence.manifest_workflow_path
        OR NEW.workflow_path <> run_evidence.workflow_path
        OR NEW.source_digest <> run_evidence.source_digest
        OR NEW.event_name <> source_evidence.manifest_event_name
        OR NEW.event_name <> run_evidence.event_name
        OR NEW.event_digest <> run_evidence.event_digest
        OR NEW.event_digest <> source_evidence.raw_event_digest
        OR NEW.git_ref <> source_evidence.manifest_git_ref
        OR NEW.git_ref <> run_evidence.git_ref
        OR NEW.workflow_plan_schema <> run_evidence.plan_schema
        OR NEW.workflow_plan_schema <> run_evidence.invocation_plan_schema
        OR NEW.plan_digest <> run_evidence.plan_digest
        OR NEW.plan_digest <> run_evidence.invocation_plan_digest
        OR NEW.logical_admission_digest <> run_evidence.admission_digest
        OR run_evidence.admission_epoch <> 4
        OR NEW.admitted_at_ms <> run_evidence.created_at_ms
        OR NEW.admitted_at_ms <> run_evidence.marker_admitted_at_ms
        OR NEW.admitted_at_ms < source_evidence.accepted_at_ms
    THEN
        RAISE EXCEPTION 'GitHub workflow-run subject evidence authority is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_run_subject_evidence_authority_exact';
    END IF;

    expected_digest = automata_github_workflow_run_subject_evidence_digest(
        NEW.tenant_id,
        NEW.repository_id,
        NEW.workflow_id,
        NEW.snapshot_id,
        NEW.run_id,
        NEW.root_invocation_id,
        NEW.provider_delivery_id,
        NEW.provider_delivery_idempotency_key,
        NEW.admission_claim_owner_id,
        NEW.admission_claim_attempt,
        NEW.admission_claim_fence,
        NEW.admission_claimed_at_ms,
        NEW.admission_claim_expires_at_ms,
        NEW.github_check_subject_id,
        NEW.github_check_head_sha,
        source_evidence.provider_connection_id,
        source_evidence.provider_installation_id,
        source_evidence.github_repository_id,
        source_evidence.github_repository_owner_id,
        source_evidence.github_repository_name,
        source_evidence.repository_visibility,
        source_evidence.provider_manifest_revision,
        source_evidence.provider_manifest_digest,
        source_evidence.authenticated_webhook_verifier_fingerprint_sha256,
        source_evidence.authenticated_webhook_verifier_revision,
        source_evidence.checks_authority_id,
        source_evidence.checks_authority_identity_digest,
        source_evidence.checks_authority_app_configuration_revision,
        source_evidence.checks_authority_policy_revision,
        source_evidence.private_source_authority_id,
        source_evidence.private_source_authority_identity_digest,
        source_evidence.private_source_authority_app_configuration_revision,
        source_evidence.private_source_authority_policy_revision,
        source_evidence.request_digest,
        source_evidence.raw_event_digest,
        source_evidence.accepted_at_ms,
        NEW.workflow_path,
        NEW.source_digest,
        NEW.event_name,
        NEW.event_digest,
        NEW.git_ref,
        NEW.workflow_plan_schema,
        NEW.plan_digest,
        NEW.logical_admission_digest,
        NEW.admitted_at_ms
    );

    IF NEW.subject_evidence_sha256 IS DISTINCT FROM expected_digest THEN
        RAISE EXCEPTION 'GitHub workflow-run subject evidence digest is not canonical'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_run_subject_evidence_canonical';
    END IF;

    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_workflow_run_subject_evidence_00_insert_guard
BEFORE INSERT ON github_workflow_run_subject_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_github_workflow_run_subject_evidence_insert_guard();

CREATE FUNCTION automata_github_workflow_run_subject_evidence_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub workflow-run subject evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_workflow_run_subject_evidence_immutable';
END;
$automata$;

CREATE TRIGGER github_workflow_run_subject_evidence_no_update_delete
BEFORE UPDATE OR DELETE ON github_workflow_run_subject_evidence
FOR EACH ROW
EXECUTE FUNCTION automata_github_workflow_run_subject_evidence_immutable();

CREATE TRIGGER github_workflow_run_subject_evidence_no_truncate
BEFORE TRUNCATE ON github_workflow_run_subject_evidence
FOR EACH STATEMENT
EXECUTE FUNCTION automata_github_workflow_run_subject_evidence_immutable();

-- The authenticated provider path marks its admission receipt at creation.
-- The deferred half of the bidirectional contract prevents that transaction
-- from committing a run without the one exact immutable evidence receipt.
CREATE FUNCTION automata_required_github_subject_evidence_committed()
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
    END IF;

    IF evidence_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'authenticated GitHub admission requires exact subject evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_admission_required_github_evidence_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_admission_require_github_evidence
AFTER INSERT OR UPDATE ON workflow_admission_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_required_github_subject_evidence_committed();
