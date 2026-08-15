ALTER TABLE github_server_service_authorities
    DROP CONSTRAINT github_server_service_authorities_permission_exact,
    DROP CONSTRAINT github_server_service_authorities_service_scope;

ALTER TABLE github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_permission_exact CHECK (
        (service_scope = 'checks_write'
            AND permission_policy = '{"checks": "write"}'::jsonb
            AND policy_digest = decode(
                '6acf4ef0f49f5935d65a42dacb8ffcd49718dfd847d802d96038d81cea869a9c',
                'hex'
            ))
        OR (service_scope = 'private_repository_source_read'
            AND permission_policy = '{"contents": "read"}'::jsonb
            AND policy_digest = decode(
                '3c2516eac095f5bda3e7d20265497325e91030d1abe5907d4fb7fefcd0aa7f57',
                'hex'
            ))
        OR (service_scope = 'workflow_permissions_read'
            AND permission_policy = '{"administration": "read"}'::jsonb
            AND policy_digest = decode(
                '8ed2a0af82c45da675ac00d905c42d8da14c97ea67427c43cc00c60a6c330a30',
                'hex'
            ))
    ),
    ADD CONSTRAINT github_server_service_authorities_service_scope CHECK (
        service_scope = ANY (ARRAY[
            'checks_write'::text,
            'private_repository_source_read'::text,
            'workflow_permissions_read'::text
        ])
    );

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
            'observe_workflow_permission_defaults'::text
        ])
    ),
    ADD CONSTRAINT github_server_service_handoffs_observation_time_shape CHECK (
        consumer_action <> 'observe_workflow_permission_defaults'
        OR required_through_ms::NUMERIC = granted_at_ms::NUMERIC + 300000
    );

CREATE TABLE github_workflow_permission_observation_candidates (
    observation_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    proposed_manifest_revision bigint NOT NULL,
    proposed_manifest_digest bytea NOT NULL,
    proposed_runtime_policy_revision bigint NOT NULL,
    proposed_runtime_policy_digest bytea NOT NULL,
    provider_installation_id bigint NOT NULL,
    github_repository_id bigint NOT NULL,
    github_repository_name text NOT NULL COLLATE pg_catalog."C",
    github_app_id bigint NOT NULL,
    github_app_client_id text NOT NULL COLLATE pg_catalog."C",
    github_app_jwt_issuer_kind text NOT NULL COLLATE pg_catalog."C",
    app_key_spki_sha256 bytea NOT NULL,
    app_configuration_revision bigint NOT NULL,
    policy_revision bigint NOT NULL,
    authority_id uuid NOT NULL,
    authority_identity_digest bytea NOT NULL,
    expected_default text NOT NULL COLLATE pg_catalog."C",
    expected_can_approve_pull_request_reviews boolean NOT NULL,
    consumer_owner_id uuid NOT NULL,
    consumer_claim_fence bigint NOT NULL,
    consumer_action text NOT NULL COLLATE pg_catalog."C",
    consumer_revision bigint NOT NULL,
    claimed_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    candidate_digest bytea NOT NULL,
    CONSTRAINT github_workflow_permission_candidates_tenant_id_unique
        UNIQUE (tenant_id, observation_id),
    CONSTRAINT github_workflow_permission_candidates_repository FOREIGN KEY (
        tenant_id, repository_id
    ) REFERENCES repositories (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_candidates_authority FOREIGN KEY (
        tenant_id, authority_id
    ) REFERENCES github_server_service_authorities (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_candidates_positive CHECK (
        proposed_manifest_revision > 0
        AND proposed_runtime_policy_revision > 0
        AND provider_installation_id > 0
        AND github_repository_id > 0
        AND github_app_id > 0
        AND app_configuration_revision > 0
        AND policy_revision > 0
        AND consumer_claim_fence = proposed_manifest_revision
        AND consumer_revision = proposed_runtime_policy_revision
        AND claimed_at_ms >= 0
        AND expires_at_ms = claimed_at_ms + 360000
    ),
    CONSTRAINT github_workflow_permission_candidates_shape CHECK (
        octet_length(proposed_manifest_digest) = 32
        AND octet_length(proposed_runtime_policy_digest) = 32
        AND octet_length(app_key_spki_sha256) = 32
        AND octet_length(authority_identity_digest) = 32
        AND octet_length(candidate_digest) = 32
        AND expected_default = ANY (ARRAY['read'::text, 'write'::text])
        AND NOT expected_can_approve_pull_request_reviews
        AND github_app_jwt_issuer_kind = ANY (
            ARRAY['app_client_id'::text, 'app_id'::text]
        )
        AND consumer_action = 'observe_workflow_permission_defaults'
    )
);

CREATE TABLE github_workflow_permission_default_observations (
    observation_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    candidate_digest bytea NOT NULL,
    handoff_id uuid NOT NULL UNIQUE,
    handoff_generation bigint NOT NULL,
    default_workflow_permissions text NOT NULL COLLATE pg_catalog."C",
    can_approve_pull_request_reviews boolean NOT NULL,
    matches_expected_default boolean NOT NULL,
    api_version text NOT NULL COLLATE pg_catalog."C",
    request_started_at_ms bigint NOT NULL,
    provider_observed_at_ms bigint NOT NULL,
    released_at_ms bigint NOT NULL,
    recorded_at_ms bigint NOT NULL,
    activated_manifest_revision bigint,
    activated_manifest_digest bytea,
    activated_runtime_policy_revision bigint,
    activated_runtime_policy_digest bytea,
    observation_digest bytea NOT NULL,
    CONSTRAINT github_workflow_permission_observations_candidate FOREIGN KEY (
        tenant_id, observation_id
    ) REFERENCES github_workflow_permission_observation_candidates (
        tenant_id, observation_id
    ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_observations_manifest FOREIGN KEY (
        tenant_id,
        repository_id,
        provider_connection_id,
        activated_manifest_revision,
        activated_manifest_digest
    ) REFERENCES github_provider_manifest_revisions (
        tenant_id,
        repository_id,
        provider_connection_id,
        manifest_revision,
        manifest_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_observations_runtime_policy FOREIGN KEY (
        tenant_id,
        repository_id,
        activated_runtime_policy_revision,
        activated_runtime_policy_digest
    ) REFERENCES workflow_runtime_policy_revisions (
        tenant_id,
        repository_id,
        policy_revision,
        policy_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_observations_handoff FOREIGN KEY (handoff_id)
        REFERENCES github_server_service_authority_handoffs (id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_observations_positive CHECK (
        handoff_generation > 0
        AND request_started_at_ms >= 0
        AND request_started_at_ms <= provider_observed_at_ms
        AND provider_observed_at_ms <= released_at_ms
        AND released_at_ms <= recorded_at_ms
    ),
    CONSTRAINT github_workflow_permission_observations_shape CHECK (
        octet_length(candidate_digest) = 32
        AND octet_length(observation_digest) = 32
        AND default_workflow_permissions = ANY (ARRAY['read'::text, 'write'::text])
        AND api_version = '2026-03-10'
        AND (
            (
                matches_expected_default
                AND activated_manifest_revision IS NOT NULL
                AND activated_manifest_digest IS NOT NULL
                AND activated_runtime_policy_revision IS NOT NULL
                AND activated_runtime_policy_digest IS NOT NULL
                AND activated_manifest_revision > 0
                AND octet_length(activated_manifest_digest) = 32
                AND activated_runtime_policy_revision > 0
                AND octet_length(activated_runtime_policy_digest) = 32
            )
            OR (
                NOT matches_expected_default
                AND activated_manifest_revision IS NULL
                AND activated_manifest_digest IS NULL
                AND activated_runtime_policy_revision IS NULL
                AND activated_runtime_policy_digest IS NULL
            )
        )
    )
);

CREATE TABLE github_workflow_permission_candidate_closures (
    observation_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    candidate_digest bytea NOT NULL,
    disposition text NOT NULL COLLATE pg_catalog."C",
    handoff_id uuid,
    handoff_generation bigint,
    released_at_ms bigint,
    closed_at_ms bigint NOT NULL,
    CONSTRAINT github_workflow_permission_closures_candidate FOREIGN KEY (
        tenant_id, observation_id
    ) REFERENCES github_workflow_permission_observation_candidates (
        tenant_id, observation_id
    ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_closures_handoff FOREIGN KEY (handoff_id)
        REFERENCES github_server_service_authority_handoffs (id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_closures_shape CHECK (
        octet_length(candidate_digest) = 32
        AND closed_at_ms >= 0
        AND (
            (
                disposition = 'absent'
                AND handoff_id IS NULL
                AND handoff_generation IS NULL
                AND released_at_ms IS NULL
            )
            OR (
                disposition = ANY (ARRAY['released'::text, 'already_released'::text])
                AND handoff_id IS NOT NULL
                AND handoff_generation > 0
                AND released_at_ms >= 0
                AND released_at_ms <= closed_at_ms
            )
        )
    )
);

CREATE TABLE github_workflow_permission_default_heads (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    manifest_revision bigint NOT NULL,
    manifest_digest bytea NOT NULL,
    runtime_policy_revision bigint NOT NULL,
    runtime_policy_digest bytea NOT NULL,
    observation_id uuid NOT NULL,
    observation_digest bytea NOT NULL,
    status text NOT NULL COLLATE pg_catalog."C",
    provider_observed_at_ms bigint NOT NULL,
    fresh_through_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT github_workflow_permission_default_heads_pkey PRIMARY KEY (
        tenant_id, repository_id, provider_connection_id
    ),
    CONSTRAINT github_workflow_permission_default_heads_repository FOREIGN KEY (
        tenant_id, repository_id
    ) REFERENCES repositories (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_default_heads_manifest FOREIGN KEY (
        tenant_id,
        repository_id,
        provider_connection_id,
        manifest_revision,
        manifest_digest
    ) REFERENCES github_provider_manifest_revisions (
        tenant_id,
        repository_id,
        provider_connection_id,
        manifest_revision,
        manifest_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_default_heads_runtime_policy FOREIGN KEY (
        tenant_id,
        repository_id,
        runtime_policy_revision,
        runtime_policy_digest
    ) REFERENCES workflow_runtime_policy_revisions (
        tenant_id,
        repository_id,
        policy_revision,
        policy_digest
    ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_default_heads_observation FOREIGN KEY (
        observation_id
    ) REFERENCES github_workflow_permission_default_observations (
        observation_id
    ) ON DELETE RESTRICT,
    CONSTRAINT github_workflow_permission_default_heads_shape CHECK (
        repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND provider_connection_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND observation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND manifest_revision > 0
        AND runtime_policy_revision > 0
        AND octet_length(manifest_digest) = 32
        AND octet_length(runtime_policy_digest) = 32
        AND octet_length(observation_digest) = 32
        AND status = ANY (ARRAY['ready'::text, 'invalid'::text])
        AND provider_observed_at_ms >= 0
        AND updated_at_ms >= provider_observed_at_ms
        AND (
            (
                status = 'ready'
                AND fresh_through_ms::NUMERIC =
                    provider_observed_at_ms::NUMERIC + 900000
            )
            OR (
                status = 'invalid'
                AND fresh_through_ms = provider_observed_at_ms
            )
        )
    )
);

CREATE INDEX github_workflow_permission_candidates_target_lookup
    ON github_workflow_permission_observation_candidates (
        tenant_id,
        repository_id,
        provider_connection_id,
        proposed_manifest_revision,
        claimed_at_ms DESC
    );

CREATE FUNCTION automata_github_workflow_permission_candidate_digest(
    candidate github_workflow_permission_observation_candidates
) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $_$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.github-workflow-permission-candidate.v2', 'UTF8'
    ) || pg_catalog.decode('00', 'hex')
    || pg_catalog.int2send(2::SMALLINT)
    || automata_digest_part(pg_catalog.convert_to((candidate).tenant_id, 'UTF8'))
    || pg_catalog.uuid_send((candidate).observation_id)
    || pg_catalog.uuid_send((candidate).repository_id)
    || pg_catalog.uuid_send((candidate).provider_connection_id)
    || pg_catalog.int8send((candidate).proposed_manifest_revision)
    || (candidate).proposed_manifest_digest
    || pg_catalog.int8send((candidate).proposed_runtime_policy_revision)
    || (candidate).proposed_runtime_policy_digest
    || pg_catalog.int8send((candidate).provider_installation_id)
    || pg_catalog.int8send((candidate).github_repository_id)
    || automata_digest_part(
        pg_catalog.convert_to((candidate).github_repository_name, 'UTF8')
    )
    || pg_catalog.int8send((candidate).github_app_id)
    || automata_digest_part(
        pg_catalog.convert_to((candidate).github_app_client_id, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.convert_to((candidate).github_app_jwt_issuer_kind, 'UTF8')
    )
    || (candidate).app_key_spki_sha256
    || pg_catalog.int8send((candidate).app_configuration_revision)
    || pg_catalog.int8send((candidate).policy_revision)
    || pg_catalog.uuid_send((candidate).authority_id)
    || (candidate).authority_identity_digest
    || automata_digest_part(
        pg_catalog.convert_to((candidate).expected_default, 'UTF8')
    )
    || CASE WHEN (candidate).expected_can_approve_pull_request_reviews
        THEN pg_catalog.decode('01', 'hex')
        ELSE pg_catalog.decode('00', 'hex')
    END
    || pg_catalog.uuid_send((candidate).observation_id)
    || pg_catalog.uuid_send((candidate).consumer_owner_id)
    || pg_catalog.int8send((candidate).consumer_claim_fence)
    || automata_digest_part(
        pg_catalog.convert_to((candidate).consumer_action, 'UTF8')
    )
    || pg_catalog.int8send((candidate).consumer_revision)
    || pg_catalog.int8send((candidate).claimed_at_ms)
    || pg_catalog.int8send((candidate).expires_at_ms)
)
$_$;

CREATE FUNCTION automata_github_workflow_permission_observation_digest(
    observation github_workflow_permission_default_observations
) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $_$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.github-workflow-permission-defaults.v2', 'UTF8'
    ) || pg_catalog.decode('00', 'hex')
    || pg_catalog.int2send(2::SMALLINT)
    || pg_catalog.uuid_send((observation).observation_id)
    || (observation).candidate_digest
    || pg_catalog.uuid_send((observation).handoff_id)
    || pg_catalog.int8send((observation).handoff_generation)
    || automata_digest_part(pg_catalog.convert_to((observation).api_version, 'UTF8'))
    || automata_digest_part(
        pg_catalog.convert_to((observation).default_workflow_permissions, 'UTF8')
    )
    || CASE WHEN (observation).can_approve_pull_request_reviews
        THEN pg_catalog.decode('01', 'hex')
        ELSE pg_catalog.decode('00', 'hex')
    END
    || CASE WHEN (observation).matches_expected_default
        THEN pg_catalog.decode('01', 'hex')
        ELSE pg_catalog.decode('00', 'hex')
    END
    || pg_catalog.int8send((observation).provider_observed_at_ms)
    || pg_catalog.int8send((observation).released_at_ms)
)
$_$;

CREATE FUNCTION automata_github_workflow_permission_candidate_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    authority github_server_service_authorities%ROWTYPE;
    repository repositories%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    SELECT * INTO repository
    FROM repositories
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.repository_id
    FOR SHARE;
    SELECT * INTO authority
    FROM github_server_service_authorities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.authority_id
    FOR SHARE;
    -- The repository/authority locks may block behind a concurrent rollout.
    -- Sample after both decision rows are stable so a candidate cannot cross
    -- its expiry boundary while waiting and retain the trigger-entry time.
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    IF repository.id IS NULL
        OR authority.id IS NULL
        OR authority.state <> 'active'
        OR authority.service_scope <> 'workflow_permissions_read'
        OR authority.repository_id <> NEW.repository_id
        OR authority.provider_connection_id <> NEW.provider_connection_id
        OR authority.provider_installation_id <> NEW.provider_installation_id
        OR authority.github_app_id <> NEW.github_app_id
        OR authority.github_app_client_id <> NEW.github_app_client_id
        OR authority.github_app_jwt_issuer_kind <> NEW.github_app_jwt_issuer_kind
        OR authority.github_repository_id <> NEW.github_repository_id
        OR authority.github_repository_name <> NEW.github_repository_name
        OR authority.app_key_spki_sha256 <> NEW.app_key_spki_sha256
        OR authority.app_configuration_revision <> NEW.app_configuration_revision
        OR authority.policy_revision <> NEW.policy_revision
        OR authority.identity_digest <> NEW.authority_identity_digest
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner || '/' || repository.name <> NEW.github_repository_name
        OR NEW.claimed_at_ms > database_now_ms + 60000
        OR NEW.expires_at_ms <= database_now_ms
        OR NEW.candidate_digest <>
            automata_github_workflow_permission_candidate_digest(NEW)
    THEN
        RAISE EXCEPTION 'GitHub workflow-permission candidate is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_permission_candidate_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_workflow_permission_observation_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate github_workflow_permission_observation_candidates%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    handoff github_server_service_authority_handoffs%ROWTYPE;
    candidate_authority_id uuid;
    current_manifest github_provider_manifest_current%ROWTYPE;
    current_policy workflow_runtime_policy_current%ROWTYPE;
    manifest_revision github_provider_manifest_revisions%ROWTYPE;
    policy_revision workflow_runtime_policy_revisions%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    SELECT authority_id INTO candidate_authority_id
    FROM github_workflow_permission_observation_candidates
    WHERE observation_id = NEW.observation_id
      AND tenant_id = NEW.tenant_id;
    IF candidate_authority_id IS NOT NULL THEN
        SELECT * INTO authority
        FROM github_server_service_authorities
        WHERE tenant_id = NEW.tenant_id
          AND id = candidate_authority_id
        FOR UPDATE;
    END IF;
    SELECT * INTO candidate
    FROM github_workflow_permission_observation_candidates
    WHERE observation_id = NEW.observation_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    SELECT * INTO handoff
    FROM github_server_service_authority_handoffs
    WHERE id = NEW.handoff_id
    FOR SHARE;
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    IF candidate.observation_id IS NULL
        OR authority.id IS NULL
        OR authority.state <> 'active'
        OR authority.service_scope <> 'workflow_permissions_read'
        OR authority.identity_digest <> candidate.authority_identity_digest
        OR handoff.id IS NULL
        OR NEW.candidate_digest <> candidate.candidate_digest
        OR EXISTS (
            SELECT 1
            FROM github_workflow_permission_candidate_closures AS closure
            WHERE closure.tenant_id = candidate.tenant_id
              AND closure.observation_id = candidate.observation_id
        )
        OR NEW.repository_id <> candidate.repository_id
        OR NEW.provider_connection_id <> candidate.provider_connection_id
        OR handoff.tenant_id <> candidate.tenant_id
        OR handoff.authority_id <> candidate.authority_id
        OR handoff.generation <> NEW.handoff_generation
        OR handoff.consumer_id <> candidate.observation_id
        OR handoff.consumer_owner_id <> candidate.consumer_owner_id
        OR handoff.consumer_claim_fence <> candidate.consumer_claim_fence
        OR handoff.consumer_action <> candidate.consumer_action
        OR handoff.consumer_revision <> candidate.consumer_revision
        OR handoff.granted_at_ms > NEW.provider_observed_at_ms
        OR NEW.request_started_at_ms <> candidate.claimed_at_ms
        OR NEW.provider_observed_at_ms > handoff.required_through_ms
        OR handoff.released_at_ms IS NULL
        OR handoff.released_at_ms <> NEW.released_at_ms
        OR NEW.released_at_ms > candidate.expires_at_ms
        OR NEW.matches_expected_default <> (
            NEW.default_workflow_permissions = candidate.expected_default
            AND NEW.can_approve_pull_request_reviews =
                candidate.expected_can_approve_pull_request_reviews
        )
        OR NEW.recorded_at_ms > database_now_ms
        OR NEW.recorded_at_ms < database_now_ms - 60000
        OR NEW.observation_digest <>
            automata_github_workflow_permission_observation_digest(NEW)
    THEN
        RAISE EXCEPTION 'GitHub workflow-permission observation is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_permission_observation_exact';
    END IF;

    IF NEW.matches_expected_default THEN
        SELECT * INTO current_manifest
        FROM github_provider_manifest_current
        WHERE tenant_id = candidate.tenant_id
          AND repository_id = candidate.repository_id
          AND provider_connection_id = candidate.provider_connection_id
        FOR SHARE;
        SELECT * INTO current_policy
        FROM workflow_runtime_policy_current
        WHERE tenant_id = candidate.tenant_id
          AND repository_id = candidate.repository_id
        FOR SHARE;
        SELECT * INTO manifest_revision
        FROM github_provider_manifest_revisions
        WHERE tenant_id = candidate.tenant_id
          AND repository_id = candidate.repository_id
          AND provider_connection_id = candidate.provider_connection_id
          AND manifest_revision = candidate.proposed_manifest_revision
          AND manifest_digest = candidate.proposed_manifest_digest
        FOR SHARE;
        SELECT * INTO policy_revision
        FROM workflow_runtime_policy_revisions
        WHERE tenant_id = candidate.tenant_id
          AND repository_id = candidate.repository_id
          AND policy_revision = candidate.proposed_runtime_policy_revision
          AND policy_digest = candidate.proposed_runtime_policy_digest
        FOR SHARE;
        -- Current-pointer locks can wait independently of the evidence locks.
        -- Re-sample before the activation freshness decision.
        database_now_ms := floor(
            extract(epoch FROM clock_timestamp()) * 1000
        )::BIGINT;
        IF current_manifest.provider_connection_id IS NULL
            OR current_policy.repository_id IS NULL
            OR manifest_revision.provider_connection_id IS NULL
            OR policy_revision.repository_id IS NULL
            OR current_manifest.manifest_revision <>
                candidate.proposed_manifest_revision
            OR current_manifest.manifest_digest <>
                candidate.proposed_manifest_digest
            OR current_policy.policy_revision <>
                candidate.proposed_runtime_policy_revision
            OR current_policy.policy_digest <>
                candidate.proposed_runtime_policy_digest
            OR manifest_revision.provider_installation_id <>
                candidate.provider_installation_id
            OR manifest_revision.github_repository_id <>
                candidate.github_repository_id
            OR manifest_revision.github_repository_name <>
                candidate.github_repository_name
            OR manifest_revision.github_app_id <> candidate.github_app_id
            OR manifest_revision.github_app_client_id <>
                candidate.github_app_client_id
            OR manifest_revision.github_app_jwt_issuer_kind <>
                candidate.github_app_jwt_issuer_kind
            OR manifest_revision.app_key_spki_sha256 <>
                candidate.app_key_spki_sha256
            OR manifest_revision.app_configuration_revision <>
                candidate.app_configuration_revision
            OR manifest_revision.policy_revision <> candidate.policy_revision
            OR manifest_revision.runtime_policy_revision <>
                candidate.proposed_runtime_policy_revision
            OR manifest_revision.runtime_policy_digest <>
                candidate.proposed_runtime_policy_digest
            OR policy_revision.state <> 'sealed'
            OR (
                CASE candidate.expected_default
                    WHEN 'read' THEN
                        pg_catalog.convert_from(
                            policy_revision.permission_policy_canonical, 'UTF8'
                        )::jsonb -> 'provider_default'
                        IS DISTINCT FROM
                            '{"contents":"read","packages":"read"}'::jsonb
                    WHEN 'write' THEN
                        pg_catalog.convert_from(
                            policy_revision.permission_policy_canonical, 'UTF8'
                        )::jsonb -> 'provider_default'
                        IS DISTINCT FROM pg_catalog.convert_from(
                            policy_revision.permission_policy_canonical, 'UTF8'
                        )::jsonb -> 'write_all'
                    ELSE TRUE
                END
            )
            OR NEW.activated_manifest_revision IS DISTINCT FROM
                candidate.proposed_manifest_revision
            OR NEW.activated_manifest_digest IS DISTINCT FROM
                candidate.proposed_manifest_digest
            OR NEW.activated_runtime_policy_revision IS DISTINCT FROM
                candidate.proposed_runtime_policy_revision
            OR NEW.activated_runtime_policy_digest IS DISTINCT FROM
                candidate.proposed_runtime_policy_digest
            OR database_now_ms > candidate.expires_at_ms
        THEN
            RAISE EXCEPTION 'matching GitHub workflow-permission activation is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_workflow_permission_activation_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_github_workflow_permission_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'GitHub workflow-permission evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE FUNCTION automata_github_workflow_permission_closure_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate github_workflow_permission_observation_candidates%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    handoff github_server_service_authority_handoffs%ROWTYPE;
    candidate_authority_id uuid;
    database_now_ms BIGINT;
BEGIN
    -- Discover the authority without taking the candidate lock, then take the
    -- same authority-first lock used by handoff acquisition and observation
    -- finalization. This serializes an absence closure against a late handoff.
    SELECT authority_id INTO candidate_authority_id
    FROM github_workflow_permission_observation_candidates
    WHERE observation_id = NEW.observation_id
      AND tenant_id = NEW.tenant_id;
    IF candidate_authority_id IS NOT NULL THEN
        SELECT * INTO authority
        FROM github_server_service_authorities
        WHERE tenant_id = NEW.tenant_id
          AND id = candidate_authority_id
        FOR UPDATE;
    END IF;
    SELECT * INTO candidate
    FROM github_workflow_permission_observation_candidates
    WHERE observation_id = NEW.observation_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    IF NEW.handoff_id IS NOT NULL THEN
        SELECT * INTO handoff
        FROM github_server_service_authority_handoffs
        WHERE id = NEW.handoff_id
        FOR SHARE;
    END IF;
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    IF candidate.observation_id IS NULL
        OR authority.id IS NULL
        OR authority.service_scope <> 'workflow_permissions_read'
        OR authority.repository_id <> candidate.repository_id
        OR authority.provider_connection_id <> candidate.provider_connection_id
        OR authority.provider_installation_id <> candidate.provider_installation_id
        OR authority.github_app_id <> candidate.github_app_id
        OR authority.github_app_client_id <> candidate.github_app_client_id
        OR authority.github_app_jwt_issuer_kind <>
            candidate.github_app_jwt_issuer_kind
        OR authority.github_repository_id <> candidate.github_repository_id
        OR authority.github_repository_name <> candidate.github_repository_name
        OR authority.app_key_spki_sha256 <> candidate.app_key_spki_sha256
        OR authority.app_configuration_revision <>
            candidate.app_configuration_revision
        OR authority.policy_revision <> candidate.policy_revision
        OR authority.identity_digest <> candidate.authority_identity_digest
        OR NEW.candidate_digest <> candidate.candidate_digest
        OR NEW.closed_at_ms > database_now_ms
        OR NEW.closed_at_ms < database_now_ms - 60000
        OR EXISTS (
            SELECT 1
            FROM github_workflow_permission_default_observations AS observation
            WHERE observation.tenant_id = candidate.tenant_id
              AND observation.observation_id = candidate.observation_id
        )
        OR (
            NEW.disposition = 'absent'
            AND EXISTS (
                SELECT 1
                FROM github_server_service_authority_handoffs AS existing
                WHERE existing.tenant_id = candidate.tenant_id
                  AND existing.authority_id = candidate.authority_id
                  AND existing.consumer_id = candidate.observation_id
                  AND existing.consumer_owner_id = candidate.consumer_owner_id
                  AND existing.consumer_claim_fence = candidate.consumer_claim_fence
                  AND existing.consumer_action = candidate.consumer_action
                  AND existing.consumer_revision = candidate.consumer_revision
            )
        )
        OR (
            NEW.disposition <> 'absent'
            AND (
                handoff.id IS NULL
                OR handoff.tenant_id <> candidate.tenant_id
                OR handoff.authority_id <> candidate.authority_id
                OR handoff.consumer_id <> candidate.observation_id
                OR handoff.consumer_owner_id <> candidate.consumer_owner_id
                OR handoff.consumer_claim_fence <> candidate.consumer_claim_fence
                OR handoff.consumer_action <> candidate.consumer_action
                OR handoff.consumer_revision <> candidate.consumer_revision
                OR handoff.generation <> NEW.handoff_generation
                OR handoff.granted_at_ms <> candidate.claimed_at_ms
                OR handoff.required_through_ms <>
                    candidate.claimed_at_ms + 300000
                OR handoff.released_at_ms IS NULL
                OR handoff.released_at_ms <> NEW.released_at_ms
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub workflow-permission candidate closure is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_permission_closure_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_workflow_permission_head_write_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    observation github_workflow_permission_default_observations%ROWTYPE;
    candidate github_workflow_permission_observation_candidates%ROWTYPE;
    current_manifest github_provider_manifest_current%ROWTYPE;
    current_policy workflow_runtime_policy_current%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    PERFORM 1
    FROM repositories
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.repository_id
    FOR SHARE;
    SELECT * INTO current_policy
    FROM workflow_runtime_policy_current
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
    FOR SHARE;
    SELECT * INTO current_manifest
    FROM github_provider_manifest_current
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND provider_connection_id = NEW.provider_connection_id
    FOR SHARE;
    SELECT * INTO observation
    FROM github_workflow_permission_default_observations
    WHERE observation_id = NEW.observation_id
    FOR SHARE;
    IF observation.observation_id IS NOT NULL THEN
        SELECT * INTO candidate
        FROM github_workflow_permission_observation_candidates
        WHERE tenant_id = observation.tenant_id
          AND observation_id = observation.observation_id
        FOR SHARE;
    END IF;
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;

    IF observation.observation_id IS NULL
        OR candidate.observation_id IS NULL
        OR observation.tenant_id <> NEW.tenant_id
        OR observation.repository_id <> NEW.repository_id
        OR observation.provider_connection_id <> NEW.provider_connection_id
        OR observation.observation_digest <> NEW.observation_digest
        OR observation.provider_observed_at_ms <> NEW.provider_observed_at_ms
        OR observation.recorded_at_ms <> NEW.updated_at_ms
        OR candidate.candidate_digest <> observation.candidate_digest
        OR candidate.proposed_manifest_revision <> NEW.manifest_revision
        OR candidate.proposed_manifest_digest <> NEW.manifest_digest
        OR candidate.proposed_runtime_policy_revision <>
            NEW.runtime_policy_revision
        OR candidate.proposed_runtime_policy_digest <>
            NEW.runtime_policy_digest
        OR current_manifest.provider_connection_id IS NULL
        OR current_manifest.manifest_revision <> NEW.manifest_revision
        OR current_manifest.manifest_digest <> NEW.manifest_digest
        OR current_policy.repository_id IS NULL
        OR current_policy.policy_revision <> NEW.runtime_policy_revision
        OR current_policy.policy_digest <> NEW.runtime_policy_digest
        OR (NEW.status = 'ready') <> observation.matches_expected_default
        OR NEW.updated_at_ms > database_now_ms
        OR NEW.updated_at_ms < database_now_ms - 60000
        OR (
            NEW.status = 'ready'
            AND NEW.fresh_through_ms::NUMERIC <>
                NEW.provider_observed_at_ms::NUMERIC + 900000
        )
        OR (
            NEW.status = 'invalid'
            AND NEW.fresh_through_ms <> NEW.provider_observed_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub workflow-permission readiness head is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_permission_default_head_exact';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.tenant_id <> NEW.tenant_id
            OR OLD.repository_id <> NEW.repository_id
            OR OLD.provider_connection_id <> NEW.provider_connection_id
            OR NEW.provider_observed_at_ms < OLD.provider_observed_at_ms
            OR (
                NEW.provider_observed_at_ms = OLD.provider_observed_at_ms
                AND (
                    OLD.status = 'invalid' AND NEW.status = 'ready'
                    OR OLD.status = NEW.status
                       AND NEW.observation_id < OLD.observation_id
                )
            )
        THEN
            RAISE EXCEPTION 'GitHub workflow-permission readiness head regressed'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_workflow_permission_default_head_monotonic';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_github_workflow_permission_head_removal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'GitHub workflow-permission readiness cannot be removed'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE FUNCTION automata_require_fresh_github_workflow_permission_defaults()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    provider_kind text;
    fresh_through_ms BIGINT;
    database_now_ms BIGINT;
BEGIN
    SELECT scm_provider INTO provider_kind
    FROM repositories
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.repository_id
    FOR SHARE;
    IF provider_kind IS NULL THEN
        RAISE EXCEPTION 'workflow runtime policy repository is unavailable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_runtime_policy_repository_required';
    END IF;
    IF provider_kind <> 'github' THEN
        RETURN NEW;
    END IF;

    SELECT head.fresh_through_ms INTO fresh_through_ms
    FROM github_workflow_permission_default_heads AS head
    JOIN github_provider_manifest_current AS current_manifest
      ON current_manifest.tenant_id = head.tenant_id
     AND current_manifest.repository_id = head.repository_id
     AND current_manifest.provider_connection_id = head.provider_connection_id
     AND current_manifest.manifest_revision = head.manifest_revision
     AND current_manifest.manifest_digest = head.manifest_digest
    JOIN workflow_runtime_policy_current AS current_policy
      ON current_policy.tenant_id = head.tenant_id
     AND current_policy.repository_id = head.repository_id
     AND current_policy.policy_revision = head.runtime_policy_revision
     AND current_policy.policy_digest = head.runtime_policy_digest
    JOIN github_workflow_permission_default_observations AS observation
      ON observation.observation_id = head.observation_id
     AND observation.observation_digest = head.observation_digest
     AND observation.tenant_id = head.tenant_id
     AND observation.repository_id = head.repository_id
     AND observation.provider_connection_id = head.provider_connection_id
    JOIN github_workflow_permission_observation_candidates AS candidate
      ON candidate.tenant_id = observation.tenant_id
     AND candidate.observation_id = observation.observation_id
     AND candidate.candidate_digest = observation.candidate_digest
    JOIN github_server_service_authorities AS authority
      ON authority.tenant_id = candidate.tenant_id
     AND authority.id = candidate.authority_id
     AND authority.identity_digest = candidate.authority_identity_digest
     AND authority.state = 'active'
     AND authority.service_scope = 'workflow_permissions_read'
    JOIN workflow_runtime_policy_revisions AS pinned_policy
      ON pinned_policy.tenant_id = NEW.tenant_id
     AND pinned_policy.repository_id = NEW.repository_id
     AND pinned_policy.policy_revision = NEW.policy_revision
     AND pinned_policy.policy_digest = NEW.policy_digest
     AND pinned_policy.state = 'sealed'
    WHERE head.tenant_id = NEW.tenant_id
      AND head.repository_id = NEW.repository_id
      AND head.status = 'ready'
      AND observation.matches_expected_default
      AND NOT observation.can_approve_pull_request_reviews
      AND CASE observation.default_workflow_permissions
          WHEN 'read' THEN
              pg_catalog.convert_from(
                  pinned_policy.permission_policy_canonical, 'UTF8'
              )::jsonb -> 'provider_default'
              IS NOT DISTINCT FROM
                  '{"contents":"read","packages":"read"}'::jsonb
          WHEN 'write' THEN
              pg_catalog.convert_from(
                  pinned_policy.permission_policy_canonical, 'UTF8'
              )::jsonb -> 'provider_default'
              IS NOT DISTINCT FROM pg_catalog.convert_from(
                  pinned_policy.permission_policy_canonical, 'UTF8'
              )::jsonb -> 'write_all'
          ELSE FALSE
      END
    FOR SHARE OF head, current_manifest, current_policy, observation,
        candidate, authority, pinned_policy;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub workflow-permission defaults are not fresh'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_permission_defaults_fresh';
    END IF;
    -- Row locks above may wait. Sample after they are acquired so an
    -- admission that crossed the exact expiry boundary cannot use an older
    -- trigger-entry timestamp.
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    IF database_now_ms >= fresh_through_ms THEN
        RAISE EXCEPTION 'GitHub workflow-permission defaults are not fresh'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_permission_defaults_fresh';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER github_workflow_permission_candidates_insert_guard
    BEFORE INSERT ON github_workflow_permission_observation_candidates
    FOR EACH ROW
    EXECUTE FUNCTION automata_github_workflow_permission_candidate_insert_guard();
CREATE TRIGGER github_workflow_permission_candidates_immutable
    BEFORE UPDATE OR DELETE ON github_workflow_permission_observation_candidates
    FOR EACH ROW
    EXECUTE FUNCTION automata_reject_github_workflow_permission_evidence_mutation();
CREATE TRIGGER github_workflow_permission_candidates_reject_truncate
    BEFORE TRUNCATE ON github_workflow_permission_observation_candidates
    FOR EACH STATEMENT
    EXECUTE FUNCTION automata_reject_github_workflow_permission_evidence_mutation();
CREATE TRIGGER github_workflow_permission_observations_insert_guard
    BEFORE INSERT ON github_workflow_permission_default_observations
    FOR EACH ROW
    EXECUTE FUNCTION automata_github_workflow_permission_observation_insert_guard();
CREATE TRIGGER github_workflow_permission_observations_immutable
    BEFORE UPDATE OR DELETE ON github_workflow_permission_default_observations
    FOR EACH ROW
    EXECUTE FUNCTION automata_reject_github_workflow_permission_evidence_mutation();
CREATE TRIGGER github_workflow_permission_observations_reject_truncate
    BEFORE TRUNCATE ON github_workflow_permission_default_observations
    FOR EACH STATEMENT
    EXECUTE FUNCTION automata_reject_github_workflow_permission_evidence_mutation();
CREATE TRIGGER github_workflow_permission_closures_insert_guard
    BEFORE INSERT ON github_workflow_permission_candidate_closures
    FOR EACH ROW
    EXECUTE FUNCTION automata_github_workflow_permission_closure_insert_guard();
CREATE TRIGGER github_workflow_permission_closures_immutable
    BEFORE UPDATE OR DELETE ON github_workflow_permission_candidate_closures
    FOR EACH ROW
    EXECUTE FUNCTION automata_reject_github_workflow_permission_evidence_mutation();
CREATE TRIGGER github_workflow_permission_closures_reject_truncate
    BEFORE TRUNCATE ON github_workflow_permission_candidate_closures
    FOR EACH STATEMENT
    EXECUTE FUNCTION automata_reject_github_workflow_permission_evidence_mutation();
CREATE TRIGGER github_workflow_permission_default_heads_write_guard
    BEFORE INSERT OR UPDATE ON github_workflow_permission_default_heads
    FOR EACH ROW
    EXECUTE FUNCTION automata_github_workflow_permission_head_write_guard();
CREATE TRIGGER github_workflow_permission_default_heads_reject_delete
    BEFORE DELETE ON github_workflow_permission_default_heads
    FOR EACH ROW
    EXECUTE FUNCTION automata_reject_github_workflow_permission_head_removal();
CREATE TRIGGER github_workflow_permission_default_heads_reject_truncate
    BEFORE TRUNCATE ON github_workflow_permission_default_heads
    FOR EACH STATEMENT
    EXECUTE FUNCTION automata_reject_github_workflow_permission_head_removal();
CREATE TRIGGER logical_workflow_runtime_policy_pins_01_permission_defaults
    BEFORE INSERT ON logical_workflow_runtime_policy_pins
    FOR EACH ROW
    EXECUTE FUNCTION automata_require_fresh_github_workflow_permission_defaults();
-- Current manifest/policy writers remain usable by non-admission bootstrap and
-- existing test/product composition. They do not grant workflow authority:
-- every new GitHub run crosses logical_workflow_runtime_policy_pins above and
-- must prove an exact, fresh Ready head. The production GitHub runtime still
-- activates observed candidates atomically; a legacy pointer-only bootstrap
-- can cause fail-closed unavailability, never admission without evidence.

CREATE FUNCTION automata_github_workflow_permission_handoff_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    issuance github_server_service_authority_issuances%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    candidate github_workflow_permission_observation_candidates%ROWTYPE;
    candidate_closed boolean;
    database_now_ms BIGINT;
BEGIN
    -- Authority first matches retirement/reconciliation lock order. Taking an
    -- issuance lock first can deadlock with retirement's authority->issuance
    -- mutation sequence.
    SELECT * INTO authority
    FROM github_server_service_authorities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.authority_id
    FOR SHARE;
    SELECT * INTO issuance
    FROM github_server_service_authority_issuances
    WHERE tenant_id = NEW.tenant_id
      AND authority_id = NEW.authority_id
      AND generation = NEW.generation
    FOR SHARE;
    SELECT * INTO candidate
    FROM github_workflow_permission_observation_candidates
    WHERE observation_id = NEW.consumer_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    SELECT EXISTS (
        SELECT 1
        FROM github_workflow_permission_candidate_closures
        WHERE observation_id = NEW.consumer_id
          AND tenant_id = NEW.tenant_id
    ) INTO candidate_closed;
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    IF issuance.authority_id IS NULL
        OR authority.id IS NULL
        OR candidate.observation_id IS NULL
        OR candidate_closed
        OR authority.state <> 'active'
        OR authority.service_scope <> 'workflow_permissions_read'
        OR authority.current_issuance_generation IS DISTINCT FROM NEW.generation
        OR issuance.state <> 'ready'
        OR issuance.state_updated_at_ms > NEW.granted_at_ms
        OR authority.state_updated_at_ms > NEW.granted_at_ms
        OR NEW.required_through_ms > issuance.provider_expires_at_ms - 60000
        OR candidate.authority_id <> authority.id
        OR candidate.authority_identity_digest <> authority.identity_digest
        OR candidate.repository_id <> authority.repository_id
        OR candidate.provider_connection_id <> authority.provider_connection_id
        OR candidate.provider_installation_id <> authority.provider_installation_id
        OR candidate.github_app_id <> authority.github_app_id
        OR candidate.github_app_client_id <> authority.github_app_client_id
        OR candidate.github_app_jwt_issuer_kind <> authority.github_app_jwt_issuer_kind
        OR candidate.github_repository_id <> authority.github_repository_id
        OR candidate.github_repository_name <> authority.github_repository_name
        OR candidate.app_key_spki_sha256 <> authority.app_key_spki_sha256
        OR candidate.app_configuration_revision <> authority.app_configuration_revision
        OR candidate.policy_revision <> authority.policy_revision
        OR NEW.consumer_owner_id <> candidate.consumer_owner_id
        OR NEW.consumer_claim_fence <> candidate.consumer_claim_fence
        OR NEW.consumer_action <> candidate.consumer_action
        OR NEW.consumer_revision <> candidate.consumer_revision
        OR candidate.claimed_at_ms <> NEW.granted_at_ms
        OR candidate.expires_at_ms <= NEW.granted_at_ms
        OR candidate.expires_at_ms <= database_now_ms
        OR database_now_ms >= NEW.required_through_ms
        OR NEW.required_through_ms::NUMERIC <>
            candidate.claimed_at_ms::NUMERIC + 300000
        OR NEW.required_through_ms >= candidate.expires_at_ms
    THEN
        RAISE EXCEPTION 'GitHub workflow-permission handoff is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_permission_handoff_exact';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER github_server_service_handoffs_insert_guard
    ON github_server_service_authority_handoffs;

CREATE TRIGGER github_server_service_handoffs_insert_guard
    BEFORE INSERT ON github_server_service_authority_handoffs
    FOR EACH ROW
    WHEN (NEW.consumer_action <> 'observe_workflow_permission_defaults')
    EXECUTE FUNCTION automata_github_server_service_handoff_insert_guard();

CREATE TRIGGER github_server_service_workflow_permission_handoff_insert_guard
    BEFORE INSERT ON github_server_service_authority_handoffs
    FOR EACH ROW
    WHEN (NEW.consumer_action = 'observe_workflow_permission_defaults')
    EXECUTE FUNCTION automata_github_workflow_permission_handoff_insert_guard();
