-- Current-only durable GitHub Checks projection. A subject exists before
-- workflow admission, remains useful when discovery/compile/admission fails,
-- and may later link to one exact admitted run. Provider I/O and credentials
-- never enter these transactions.

CREATE TABLE github_check_subjects (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_delivery_id UUID NOT NULL,
    subject_key TEXT COLLATE "C" NOT NULL,
    provider_connection_id UUID NOT NULL,
    provider_installation_id BIGINT NOT NULL,
    github_repository_id BIGINT NOT NULL,
    github_app_id BIGINT NOT NULL,
    head_sha BYTEA NOT NULL,
    check_name TEXT COLLATE "C" NOT NULL,
    external_id TEXT COLLATE "C" NOT NULL,
    workflow_run_id UUID,
    linked_at_ms BIGINT,
    desired_state TEXT NOT NULL DEFAULT 'queued',
    desired_conclusion TEXT,
    terminal_cause TEXT,
    desired_revision BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    desired_updated_at_ms BIGINT NOT NULL,
    CONSTRAINT github_check_subjects_tenant_id_unique UNIQUE (tenant_id, id),
    CONSTRAINT github_check_subjects_external_id_unique UNIQUE (
        provider_connection_id, external_id
    ),
    CONSTRAINT github_check_subjects_delivery_key_unique UNIQUE (
        provider_delivery_id, subject_key
    ),
    CONSTRAINT github_check_subjects_tenant_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_check_subjects_tenant_delivery
        FOREIGN KEY (provider_delivery_id, tenant_id)
        REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT github_check_subjects_repository_run
        FOREIGN KEY (repository_id, workflow_run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_check_subjects_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND provider_delivery_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (
            workflow_run_id IS NULL
            OR workflow_run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        )
    ),
    CONSTRAINT github_check_subjects_numeric_identity CHECK (
        provider_installation_id > 0
        AND github_repository_id > 0
        AND github_app_id > 0
    ),
    CONSTRAINT github_check_subjects_sha CHECK (
        octet_length(head_sha) = 20
        AND head_sha <> decode(repeat('00', 20), 'hex')
    ),
    CONSTRAINT github_check_subjects_key_shape CHECK (
        octet_length(subject_key) BETWEEN 1 AND 1024
        AND btrim(subject_key) = subject_key
        AND subject_key !~ '[[:cntrl:]\\]'
        AND left(subject_key, 1) <> '/'
        AND subject_key !~ '(^|/)(\.|\.\.)(/|$)'
        AND subject_key !~ '//'
    ),
    CONSTRAINT github_check_subjects_name_shape CHECK (
        octet_length(check_name) BETWEEN 1 AND 255
        AND check_name = btrim(check_name)
        AND check_name ~ '^[ -~]+$'
    ),
    CONSTRAINT github_check_subjects_external_id_exact CHECK (
        external_id = 'automata-check:' || id::TEXT
        AND octet_length(external_id) <= 1024
    ),
    CONSTRAINT github_check_subjects_link_shape CHECK (
        (workflow_run_id IS NULL AND linked_at_ms IS NULL)
        OR (workflow_run_id IS NOT NULL AND linked_at_ms >= created_at_ms)
    ),
    CONSTRAINT github_check_subjects_desired_shape CHECK (
        desired_revision > 0
        AND created_at_ms >= 0
        AND desired_updated_at_ms >= created_at_ms
        AND (
            desired_state IN ('queued', 'in_progress')
            AND desired_conclusion IS NULL
            AND terminal_cause IS NULL
            OR desired_state = 'completed'
            AND desired_conclusion IN (
                'action_required', 'cancelled', 'failure',
                'success', 'skipped', 'timed_out'
            )
            AND terminal_cause IN (
                'workflow_success', 'workflow_skipped', 'workflow_failure',
                'workflow_cancelled', 'workflow_timed_out',
                'provider_unknown', 'system_unknown'
            )
        )
    ),
    CONSTRAINT github_check_subjects_terminal_mapping CHECK (
        desired_state <> 'completed'
        OR CASE terminal_cause
            WHEN 'workflow_success' THEN desired_conclusion = 'success'
            WHEN 'workflow_skipped' THEN desired_conclusion = 'skipped'
            WHEN 'workflow_failure' THEN desired_conclusion = 'failure'
            WHEN 'workflow_cancelled' THEN desired_conclusion = 'cancelled'
            WHEN 'workflow_timed_out' THEN desired_conclusion = 'timed_out'
            WHEN 'provider_unknown' THEN desired_conclusion = 'action_required'
            WHEN 'system_unknown' THEN desired_conclusion = 'failure'
            ELSE FALSE
        END
    )
);

CREATE INDEX github_check_subjects_run
    ON github_check_subjects (tenant_id, repository_id, workflow_run_id)
    WHERE workflow_run_id IS NOT NULL;

CREATE TABLE github_check_projection_outbox (
    subject_id UUID PRIMARY KEY
        REFERENCES github_check_subjects(id) ON DELETE RESTRICT,
    state TEXT NOT NULL DEFAULT 'pending',
    attempted_revision BIGINT,
    attempt_count SMALLINT NOT NULL DEFAULT 0,
    claim_fence BIGINT NOT NULL DEFAULT 0,
    claim_owner_id UUID,
    claim_action TEXT,
    claimed_desired_revision BIGINT,
    claimed_desired_state TEXT,
    claimed_desired_conclusion TEXT,
    claimed_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    next_attempt_at_ms BIGINT,
    last_failure_kind TEXT COLLATE "C",
    external_suite_id BIGINT,
    external_run_id BIGINT,
    external_bound_at_ms BIGINT,
    create_owner_id UUID,
    create_fence BIGINT,
    create_started_at_ms BIGINT,
    create_issue_expires_at_ms BIGINT,
    reconcile_not_before_ms BIGINT,
    next_reconcile_at_ms BIGINT,
    projected_revision BIGINT NOT NULL DEFAULT 0,
    provider_state TEXT,
    provider_conclusion TEXT,
    provider_observed_at_ms BIGINT,
    blocked_reason TEXT,
    state_updated_at_ms BIGINT NOT NULL,
    CONSTRAINT github_check_projection_outbox_state CHECK (
        state IN (
            'pending', 'claimed', 'retry', 'create_indeterminate',
            'delivered', 'blocked'
        )
    ),
    CONSTRAINT github_check_projection_outbox_attempt CHECK (
        attempt_count BETWEEN 0 AND 64
        AND claim_fence >= 0
        AND (attempted_revision IS NULL OR attempted_revision > 0)
    ),
    CONSTRAINT github_check_projection_outbox_external CHECK (
        (external_suite_id IS NULL OR external_suite_id > 0)
        AND (external_run_id IS NULL OR external_run_id > 0)
        AND (external_run_id IS NULL OR external_suite_id IS NOT NULL)
        AND (
            external_run_id IS NULL AND external_bound_at_ms IS NULL
            OR external_run_id IS NOT NULL AND external_bound_at_ms >= 0
        )
    ),
    CONSTRAINT github_check_projection_outbox_claim_shape CHECK (
        state <> 'claimed'
        AND claim_owner_id IS NULL
        AND claim_action IS NULL
        AND claimed_desired_revision IS NULL
        AND claimed_desired_state IS NULL
        AND claimed_desired_conclusion IS NULL
        AND claimed_at_ms IS NULL
        AND claim_expires_at_ms IS NULL
        OR state = 'claimed'
        AND claim_owner_id IS NOT NULL
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_action IN (
            'ensure_suite', 'prepare_run_create',
            'reconcile_run_create', 'publish'
        )
        AND claimed_desired_revision > 0
        AND claimed_desired_state IN ('queued', 'in_progress', 'completed')
        AND (
            claimed_desired_state = 'completed'
            AND claimed_desired_conclusion IN (
                'action_required', 'cancelled', 'failure',
                'success', 'skipped', 'timed_out'
            )
            OR claimed_desired_state <> 'completed'
            AND claimed_desired_conclusion IS NULL
        )
        AND claimed_at_ms >= 0
        AND claim_expires_at_ms > claimed_at_ms
        AND claim_expires_at_ms - claimed_at_ms <= 900000
    ),
    CONSTRAINT github_check_projection_outbox_action_shape CHECK (
        state <> 'claimed'
        OR CASE claim_action
            WHEN 'ensure_suite' THEN external_suite_id IS NULL
                AND external_run_id IS NULL
            WHEN 'prepare_run_create' THEN external_suite_id IS NOT NULL
                AND external_run_id IS NULL
                AND create_started_at_ms IS NULL
            WHEN 'reconcile_run_create' THEN external_suite_id IS NOT NULL
                AND external_run_id IS NULL
                AND create_started_at_ms IS NOT NULL
            WHEN 'publish' THEN external_suite_id IS NOT NULL
                AND external_run_id IS NOT NULL
            ELSE FALSE
        END
    ),
    CONSTRAINT github_check_projection_outbox_retry_shape CHECK (
        state = 'retry'
        AND next_attempt_at_ms > state_updated_at_ms
        AND next_attempt_at_ms - state_updated_at_ms <= 86400000
        AND last_failure_kind IS NOT NULL
        OR state <> 'retry'
        AND next_attempt_at_ms IS NULL
        AND last_failure_kind IS NULL
    ),
    CONSTRAINT github_check_projection_outbox_failure_shape CHECK (
        last_failure_kind IS NULL OR (
            octet_length(last_failure_kind) BETWEEN 1 AND 128
            AND last_failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        )
    ),
    CONSTRAINT github_check_projection_outbox_create_shape CHECK (
        create_started_at_ms IS NULL
        AND create_owner_id IS NULL
        AND create_fence IS NULL
        AND create_issue_expires_at_ms IS NULL
        AND reconcile_not_before_ms IS NULL
        AND next_reconcile_at_ms IS NULL
        OR create_started_at_ms >= 0
        AND create_owner_id IS NOT NULL
        AND create_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND create_fence > 0
        AND create_issue_expires_at_ms > create_started_at_ms
        AND create_issue_expires_at_ms - create_started_at_ms <= 900000
        AND reconcile_not_before_ms > create_issue_expires_at_ms
        AND reconcile_not_before_ms - create_issue_expires_at_ms <= 420000
        AND next_reconcile_at_ms >= reconcile_not_before_ms
        AND external_suite_id IS NOT NULL
        AND external_run_id IS NULL
    ),
    CONSTRAINT github_check_projection_outbox_indeterminate_shape CHECK (
        state <> 'create_indeterminate'
        OR create_started_at_ms IS NOT NULL
    ),
    CONSTRAINT github_check_projection_outbox_provider_shape CHECK (
        projected_revision >= 0
        AND (
            provider_state IS NULL
            AND provider_conclusion IS NULL
            AND provider_observed_at_ms IS NULL
            OR provider_state IN ('queued', 'in_progress')
            AND provider_conclusion IS NULL
            AND provider_observed_at_ms >= 0
            AND external_run_id IS NOT NULL
            OR provider_state = 'completed'
            AND provider_conclusion IN (
                'action_required', 'cancelled', 'failure',
                'success', 'skipped', 'timed_out'
            )
            AND provider_observed_at_ms >= 0
            AND external_run_id IS NOT NULL
        )
    ),
    CONSTRAINT github_check_projection_outbox_delivery_shape CHECK (
        state <> 'delivered'
        OR projected_revision > 0
        AND provider_state IS NOT NULL
        AND external_run_id IS NOT NULL
    ),
    CONSTRAINT github_check_projection_outbox_block_shape CHECK (
        state = 'blocked' AND blocked_reason IN (
            'ambiguous_create', 'attempt_limit'
        )
        OR state <> 'blocked' AND blocked_reason IS NULL
    ),
    CONSTRAINT github_check_projection_outbox_time CHECK (state_updated_at_ms >= 0)
);

CREATE INDEX github_check_projection_outbox_eligible
    ON github_check_projection_outbox (
        state, next_attempt_at_ms, next_reconcile_at_ms, state_updated_at_ms, subject_id
    ) WHERE state IN ('pending', 'retry', 'create_indeterminate', 'claimed');

CREATE UNIQUE INDEX github_check_projection_external_run_unique
    ON github_check_projection_outbox (external_run_id)
    WHERE external_run_id IS NOT NULL;

CREATE FUNCTION automata_create_github_check_projection_outbox()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    INSERT INTO github_check_projection_outbox (subject_id, state_updated_at_ms)
    VALUES (NEW.id, NEW.created_at_ms);
    RETURN NULL;
END;
$automata$;

CREATE TRIGGER github_check_subjects_create_projection_outbox
AFTER INSERT ON github_check_subjects
FOR EACH ROW EXECUTE FUNCTION automata_create_github_check_projection_outbox();

-- Direct insertion is accepted only when delivery, configured repository, and
-- all provider routing identities agree exactly. This protects the boundary
-- even when SQL is used outside the Rust adapter.
CREATE FUNCTION automata_github_check_subject_insert_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
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

    SELECT * INTO delivery
    FROM provider_delivery_inbox
    WHERE id = NEW.provider_delivery_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    SELECT * INTO repository
    FROM repositories
    WHERE id = NEW.repository_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    IF NOT FOUND
        OR delivery.id IS NULL
        OR delivery.provider <> 'github'
        OR delivery.connection_id <> NEW.provider_connection_id
        OR delivery.installation_id <> NEW.provider_installation_id
        OR delivery.provider_repository_id <> NEW.github_repository_id
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
    THEN
        RAISE EXCEPTION 'GitHub Check subject authority is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_authority_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_check_subjects_insert_guard
BEFORE INSERT ON github_check_subjects
FOR EACH ROW EXECUTE FUNCTION automata_github_check_subject_insert_guard();

CREATE FUNCTION automata_github_check_subject_update_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    run_row workflow_runs%ROWTYPE;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_delivery_id IS DISTINCT FROM OLD.provider_delivery_id
        OR NEW.subject_key IS DISTINCT FROM OLD.subject_key
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.provider_installation_id IS DISTINCT FROM OLD.provider_installation_id
        OR NEW.github_repository_id IS DISTINCT FROM OLD.github_repository_id
        OR NEW.github_app_id IS DISTINCT FROM OLD.github_app_id
        OR NEW.head_sha IS DISTINCT FROM OLD.head_sha
        OR NEW.check_name IS DISTINCT FROM OLD.check_name
        OR NEW.external_id IS DISTINCT FROM OLD.external_id
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check subject identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_identity_immutable';
    END IF;

    IF OLD.workflow_run_id IS NOT NULL
        AND (
            NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id
            OR NEW.linked_at_ms IS DISTINCT FROM OLD.linked_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub Check run linkage is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_run_immutable';
    END IF;
    IF OLD.workflow_run_id IS NULL AND NEW.workflow_run_id IS NOT NULL THEN
        SELECT * INTO run_row
        FROM workflow_runs
        WHERE repository_id = NEW.repository_id
          AND id = NEW.workflow_run_id
        FOR SHARE;
        IF NOT FOUND OR run_row.head_sha IS DISTINCT FROM NEW.head_sha THEN
            RAISE EXCEPTION 'GitHub Check run does not match repository and SHA'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_run_exact';
        END IF;
    ELSIF NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id
        OR NEW.linked_at_ms IS DISTINCT FROM OLD.linked_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check run linkage transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_run_transition';
    END IF;

    IF NEW.desired_state IS DISTINCT FROM OLD.desired_state
        OR NEW.desired_conclusion IS DISTINCT FROM OLD.desired_conclusion
        OR NEW.terminal_cause IS DISTINCT FROM OLD.terminal_cause
    THEN
        IF OLD.desired_state = 'completed'
            OR NEW.desired_revision <> OLD.desired_revision + 1
            OR NEW.desired_updated_at_ms < OLD.desired_updated_at_ms
            OR NOT (
                OLD.desired_state = 'queued'
                AND NEW.desired_state IN ('in_progress', 'completed')
                OR OLD.desired_state = 'in_progress'
                AND NEW.desired_state = 'completed'
            )
        THEN
            RAISE EXCEPTION 'GitHub Check desired transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_desired_transition';
        END IF;
    ELSIF NEW.desired_revision IS DISTINCT FROM OLD.desired_revision
        OR NEW.desired_updated_at_ms IS DISTINCT FROM OLD.desired_updated_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check desired revision changed without state'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_desired_revision_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_check_subjects_update_guard
BEFORE UPDATE ON github_check_subjects
FOR EACH ROW EXECUTE FUNCTION automata_github_check_subject_update_guard();

-- A newer desired revision wakes safe retry/delivered rows. It never discards
-- a live claim, create uncertainty, or an ambiguity/attempt-limit block.
CREATE FUNCTION automata_wake_github_check_projection()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.desired_revision <> OLD.desired_revision THEN
        UPDATE github_check_projection_outbox
        SET state = 'pending',
            next_attempt_at_ms = NULL,
            last_failure_kind = NULL,
            blocked_reason = NULL,
            state_updated_at_ms = NEW.desired_updated_at_ms
        WHERE subject_id = NEW.id
          AND state IN ('pending', 'retry', 'delivered');
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE TRIGGER github_check_subjects_wake_projection
AFTER UPDATE ON github_check_subjects
FOR EACH ROW EXECUTE FUNCTION automata_wake_github_check_projection();

CREATE FUNCTION automata_github_check_outbox_update_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    subject github_check_subjects%ROWTYPE;
BEGIN
    IF NEW.subject_id IS DISTINCT FROM OLD.subject_id
        OR NEW.claim_fence < OLD.claim_fence
        OR NEW.projected_revision < OLD.projected_revision
        OR NEW.state_updated_at_ms < OLD.state_updated_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check outbox monotonic identity regressed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_outbox_monotonic';
    END IF;
    IF NEW.claim_fence <> OLD.claim_fence
        AND (
            NEW.state <> 'claimed'
            OR NEW.claim_fence <> OLD.claim_fence + 1
        )
    THEN
        RAISE EXCEPTION 'GitHub Check claims require the next fencing token'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_claim_fence_exact';
    END IF;
    IF OLD.external_suite_id IS NOT NULL
        AND NEW.external_suite_id IS DISTINCT FROM OLD.external_suite_id
        OR OLD.external_run_id IS NOT NULL
        AND NEW.external_run_id IS DISTINCT FROM OLD.external_run_id
        OR OLD.external_bound_at_ms IS NOT NULL
        AND NEW.external_bound_at_ms IS DISTINCT FROM OLD.external_bound_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check external identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_external_immutable';
    END IF;
    IF OLD.external_suite_id IS NULL AND NEW.external_suite_id IS NOT NULL
        AND NOT (
            OLD.state = 'claimed'
            AND OLD.claim_action = 'ensure_suite'
            AND NEW.state = 'pending'
        )
    THEN
        RAISE EXCEPTION 'GitHub Check suite binding did not close an ensure claim'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_suite_binding_exact';
    END IF;
    IF OLD.external_run_id IS NULL AND NEW.external_run_id IS NOT NULL
        AND NOT (
            NEW.external_suite_id IS NOT DISTINCT FROM OLD.external_suite_id
            AND NEW.provider_state = 'queued'
            AND NEW.provider_conclusion IS NULL
            AND (
                OLD.state = 'create_indeterminate'
                OR OLD.state = 'claimed'
                   AND OLD.claim_action = 'reconcile_run_create'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub Check Run binding lacks create/reconciliation evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_run_binding_exact';
    END IF;
    IF NEW.state = 'create_indeterminate'
        AND OLD.state <> 'create_indeterminate'
        AND NOT (
            OLD.state = 'claimed'
            AND OLD.claim_action = 'prepare_run_create'
            AND OLD.create_started_at_ms IS NULL
            AND NEW.create_owner_id IS NOT DISTINCT FROM OLD.claim_owner_id
            AND NEW.create_fence IS NOT DISTINCT FROM OLD.claim_fence
            AND NEW.create_started_at_ms >= OLD.claimed_at_ms
            AND NEW.create_started_at_ms < OLD.claim_expires_at_ms
            AND NEW.create_issue_expires_at_ms IS NOT DISTINCT FROM OLD.claim_expires_at_ms
            AND NEW.next_reconcile_at_ms IS NOT DISTINCT FROM NEW.reconcile_not_before_ms
            OR OLD.state = 'claimed'
            AND OLD.claim_action = 'reconcile_run_create'
            AND OLD.attempt_count < 64
            AND NEW.create_owner_id IS NOT DISTINCT FROM OLD.create_owner_id
            AND NEW.create_fence IS NOT DISTINCT FROM OLD.create_fence
            AND NEW.create_started_at_ms IS NOT DISTINCT FROM OLD.create_started_at_ms
            AND NEW.create_issue_expires_at_ms IS NOT DISTINCT FROM OLD.create_issue_expires_at_ms
            AND NEW.reconcile_not_before_ms IS NOT DISTINCT FROM OLD.reconcile_not_before_ms
            AND NEW.next_reconcile_at_ms IS DISTINCT FROM OLD.next_reconcile_at_ms
            AND NEW.next_reconcile_at_ms > NEW.state_updated_at_ms
            AND NEW.next_reconcile_at_ms - NEW.state_updated_at_ms <= 86400000
            AND NEW.blocked_reason IS NULL
        )
    THEN
        RAISE EXCEPTION 'GitHub Check create cutoff must consume its exact claim'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_create_fence_exact';
    END IF;
    IF OLD.create_started_at_ms IS NOT NULL
        AND (
            NEW.create_owner_id IS DISTINCT FROM OLD.create_owner_id
            OR NEW.create_fence IS DISTINCT FROM OLD.create_fence
            OR NEW.create_started_at_ms IS DISTINCT FROM OLD.create_started_at_ms
            OR NEW.create_issue_expires_at_ms IS DISTINCT FROM OLD.create_issue_expires_at_ms
            OR NEW.reconcile_not_before_ms IS DISTINCT FROM OLD.reconcile_not_before_ms
        )
        AND NOT (
            NEW.create_owner_id IS NULL
            AND NEW.create_fence IS NULL
            AND NEW.create_started_at_ms IS NULL
            AND NEW.create_issue_expires_at_ms IS NULL
            AND NEW.reconcile_not_before_ms IS NULL
            AND NEW.next_reconcile_at_ms IS NULL
            AND (
                OLD.external_run_id IS NULL
                AND NEW.external_run_id IS NOT NULL
                OR OLD.state = 'create_indeterminate'
                AND OLD.next_reconcile_at_ms IS NOT DISTINCT FROM OLD.reconcile_not_before_ms
                AND NEW.external_run_id IS NULL
                AND (
                    OLD.attempt_count < 64
                    AND NEW.state = 'retry'
                    AND NEW.last_failure_kind = 'create_not_issued'
                    OR OLD.attempt_count >= 64
                    AND NEW.state = 'blocked'
                    AND NEW.blocked_reason = 'attempt_limit'
                )
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub Check create evidence changed outside exact bind or unissued release'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_create_evidence_immutable';
    END IF;
    IF OLD.create_started_at_ms IS NOT NULL
        AND NEW.create_started_at_ms IS NOT NULL
        AND NEW.next_reconcile_at_ms IS DISTINCT FROM OLD.next_reconcile_at_ms
        AND NOT (
            OLD.state = 'claimed'
            AND OLD.claim_action = 'reconcile_run_create'
            AND NEW.next_reconcile_at_ms > NEW.state_updated_at_ms
            AND NEW.next_reconcile_at_ms - NEW.state_updated_at_ms <= 86400000
            AND (
                OLD.attempt_count < 64
                AND NEW.state = 'create_indeterminate'
                AND NEW.blocked_reason IS NULL
                OR OLD.attempt_count >= 64
                AND NEW.state = 'blocked'
                AND NEW.blocked_reason = 'attempt_limit'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub Check next reconciliation time lacks exact missing evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_next_reconcile_exact';
    END IF;
    IF NEW.state = 'claimed' AND NEW.claim_fence <> OLD.claim_fence THEN
        SELECT * INTO subject
        FROM github_check_subjects
        WHERE id = NEW.subject_id;
        IF NOT FOUND
            OR NEW.attempted_revision <> subject.desired_revision
            OR NEW.claimed_desired_revision <> subject.desired_revision
            OR NEW.claimed_desired_state <> subject.desired_state
            OR NEW.claimed_desired_conclusion IS DISTINCT FROM subject.desired_conclusion
            OR NEW.attempt_count <> (CASE
                WHEN OLD.attempted_revision IS DISTINCT FROM subject.desired_revision
                    THEN 1
                ELSE OLD.attempt_count + 1
            END)
        THEN
            RAISE EXCEPTION 'GitHub Check claim snapshot is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_projection_claim_snapshot_exact';
        END IF;
    END IF;
    IF (
        NEW.provider_state IS DISTINCT FROM OLD.provider_state
        OR NEW.provider_conclusion IS DISTINCT FROM OLD.provider_conclusion
        OR NEW.provider_observed_at_ms IS DISTINCT FROM OLD.provider_observed_at_ms
        OR NEW.projected_revision IS DISTINCT FROM OLD.projected_revision
    ) AND NOT (
        OLD.external_run_id IS NULL
        AND NEW.external_run_id IS NOT NULL
        AND NEW.provider_state = 'queued'
        AND NEW.provider_conclusion IS NULL
        OR OLD.state = 'claimed'
        AND OLD.claim_action = 'publish'
        AND NEW.projected_revision = OLD.claimed_desired_revision
        AND NEW.provider_state = OLD.claimed_desired_state
        AND NEW.provider_conclusion IS NOT DISTINCT FROM OLD.claimed_desired_conclusion
    )
    THEN
        RAISE EXCEPTION 'GitHub Check provider observation lacks exact claim evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_provider_observation_exact';
    END IF;
    IF NEW.state = 'delivered' THEN
        SELECT * INTO subject
        FROM github_check_subjects
        WHERE id = NEW.subject_id;
        IF NOT FOUND
            OR NEW.projected_revision <> subject.desired_revision
            OR NEW.provider_state <> subject.desired_state
            OR NEW.provider_conclusion IS DISTINCT FROM subject.desired_conclusion
        THEN
            RAISE EXCEPTION 'GitHub Check delivered projection is not current and exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_projection_delivery_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_check_projection_outbox_update_guard
BEFORE UPDATE ON github_check_projection_outbox
FOR EACH ROW EXECUTE FUNCTION automata_github_check_outbox_update_guard();

CREATE FUNCTION automata_reject_github_check_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub Check durable evidence cannot be removed'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_check_evidence_removal_forbidden';
END;
$automata$;

CREATE TRIGGER github_check_subjects_no_delete
BEFORE DELETE ON github_check_subjects
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_check_removal();

CREATE TRIGGER github_check_subjects_no_truncate
BEFORE TRUNCATE ON github_check_subjects
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_check_removal();

CREATE TRIGGER github_check_projection_outbox_no_delete
BEFORE DELETE ON github_check_projection_outbox
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_check_removal();

CREATE TRIGGER github_check_projection_outbox_no_truncate
BEFORE TRUNCATE ON github_check_projection_outbox
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_check_removal();
