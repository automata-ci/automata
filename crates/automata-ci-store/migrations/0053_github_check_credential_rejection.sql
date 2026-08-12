-- A locally unavailable immutable Checks authority is terminal for that exact
-- projection.  This is distinct from a provider HTTP rejection: no provider
-- request was made, and the historical delivery evidence remains unchanged.
ALTER TABLE github_check_projection_outbox
    DROP CONSTRAINT github_check_projection_outbox_block_shape,
    ADD CONSTRAINT github_check_projection_outbox_block_shape CHECK (
        state = 'blocked' AND blocked_reason IN (
            'ambiguous_create', 'attempt_limit', 'credential_rejected'
        )
        OR state <> 'blocked' AND blocked_reason IS NULL
    );

-- Only an exact live claim may record local credential rejection.  Once
-- recorded, the block is immutable even if a newer desired revision appears.
CREATE FUNCTION automata_github_check_credential_rejection_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    expected github_check_projection_outbox%ROWTYPE;
BEGIN
    IF OLD.state = 'blocked' AND OLD.blocked_reason = 'credential_rejected' THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'GitHub Check credential-rejection evidence is immutable'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_projection_credential_rejection_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.state = 'blocked' AND NEW.blocked_reason = 'credential_rejected' THEN
        expected := OLD;
        expected.state := 'blocked';
        expected.claim_owner_id := NULL;
        expected.claim_action := NULL;
        expected.claimed_desired_revision := NULL;
        expected.claimed_desired_state := NULL;
        expected.claimed_desired_conclusion := NULL;
        expected.claimed_at_ms := NULL;
        expected.claim_expires_at_ms := NULL;
        expected.next_attempt_at_ms := NULL;
        expected.last_failure_kind := NULL;
        expected.blocked_reason := 'credential_rejected';
        expected.state_updated_at_ms := NEW.state_updated_at_ms;

        IF OLD.state <> 'claimed'
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.state_updated_at_ms >= OLD.claim_expires_at_ms
            OR NEW IS DISTINCT FROM expected
        THEN
            RAISE EXCEPTION 'GitHub Check credential rejection did not consume its exact live claim'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_projection_credential_rejection_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_check_projection_outbox_00_credential_rejection_guard
BEFORE UPDATE ON github_check_projection_outbox
FOR EACH ROW
EXECUTE FUNCTION automata_github_check_credential_rejection_guard();

-- Policy/App revision rotation may leave historical authorities active while
-- admitted work drains.  Preserve those rows when their complete operational
-- broker route is still the current route.  Retire only historical rows whose
-- route cannot be serviced by the current manifest, including obsolete
-- Private-source authority after a repository becomes Public.
LOCK TABLE github_provider_manifest_current, github_provider_manifest_revisions
    IN SHARE MODE;
LOCK TABLE github_server_service_authorities,
           github_server_service_authority_issuances
    IN SHARE ROW EXCLUSIVE MODE;

CREATE TEMPORARY TABLE automata_migration_0053_retire_authorities (
    authority_id UUID PRIMARY KEY,
    transition_at_ms BIGINT NOT NULL
) ON COMMIT DROP;

-- Product runtime explicitly supports the GitHub broker-policy v1 predecessor:
-- v1 requested the same least-authority token but rejected GitHub's unavoidable
-- implicit metadata:read response permission.  These are the exact v1 product
-- configuration fingerprints for the two closed service scopes.  Preserve no
-- other historical fingerprint; unknown policy remains an incompatible route.
CREATE TEMPORARY TABLE automata_migration_0053_compatible_routes (
    service_scope TEXT PRIMARY KEY,
    configuration_fingerprint BYTEA NOT NULL CHECK (
        octet_length(configuration_fingerprint) = 32
    )
) ON COMMIT DROP;

INSERT INTO automata_migration_0053_compatible_routes (
    service_scope, configuration_fingerprint
) VALUES
    (
        'checks_write',
        decode(
            '86db54f098adc51219d176555d5f7b5461a4c45ddd0625393846b1b3a5ae6543',
            'hex'
        )
    ),
    (
        'private_repository_source_read',
        decode(
            '878f4bd01bfe4b04e84d9b9eee32667d31d55feebe78a7b2f59ed715b1145b32',
            'hex'
        )
    );

CREATE TEMPORARY TABLE automata_migration_0053_manifest_scopes
ON COMMIT DROP
AS
WITH current_manifests AS MATERIALIZED (
    SELECT revision.*
    FROM github_provider_manifest_current AS current
    JOIN github_provider_manifest_revisions AS revision
      ON revision.tenant_id = current.tenant_id
     AND revision.repository_id = current.repository_id
     AND revision.provider_connection_id = current.provider_connection_id
     AND revision.manifest_revision = current.manifest_revision
     AND revision.manifest_digest = current.manifest_digest
), manifest_scopes AS MATERIALIZED (
    SELECT manifest.*, 'checks_write'::TEXT AS service_scope
    FROM current_manifests AS manifest
    UNION ALL
    SELECT manifest.*, 'private_repository_source_read'::TEXT AS service_scope
    FROM current_manifests AS manifest
    WHERE manifest.repository_source_authentication =
          'github_app_installation_token'
)
SELECT * FROM manifest_scopes;

CREATE TEMPORARY TABLE automata_migration_0053_current_routes
ON COMMIT DROP
AS
SELECT scope.tenant_id,
       scope.repository_id,
       scope.provider_connection_id,
       scope.repository_source_authentication,
       authority.id AS authority_id,
       authority.provider_installation_id,
       authority.github_app_id,
       authority.github_app_client_id,
       authority.github_app_jwt_issuer_kind,
       authority.github_repository_id,
       authority.github_repository_name,
       authority.service_scope,
       authority.app_key_spki_sha256,
       authority.configuration_fingerprint
FROM automata_migration_0053_manifest_scopes AS scope
JOIN github_server_service_authorities AS authority
  ON authority.tenant_id = scope.tenant_id
 AND authority.repository_id = scope.repository_id
 AND authority.provider_connection_id = scope.provider_connection_id
 AND authority.provider_installation_id = scope.provider_installation_id
 AND authority.github_app_id = scope.github_app_id
 AND authority.github_app_client_id = scope.github_app_client_id
 AND authority.github_app_jwt_issuer_kind = scope.github_app_jwt_issuer_kind
 AND authority.github_repository_id = scope.github_repository_id
 AND authority.github_repository_name = scope.github_repository_name
 AND authority.service_scope = scope.service_scope
 AND authority.app_key_spki_sha256 = scope.app_key_spki_sha256
 AND authority.app_configuration_revision = scope.app_configuration_revision
 AND authority.policy_revision = scope.policy_revision
 AND authority.state = 'active';

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM automata_migration_0053_manifest_scopes AS scope
        LEFT JOIN automata_migration_0053_current_routes AS route
          ON route.tenant_id = scope.tenant_id
         AND route.repository_id = scope.repository_id
         AND route.provider_connection_id = scope.provider_connection_id
         AND route.service_scope = scope.service_scope
        GROUP BY scope.tenant_id, scope.repository_id,
                 scope.provider_connection_id, scope.service_scope
        HAVING count(route.authority_id) <> 1
    ) THEN
        RAISE EXCEPTION 'current GitHub manifest scope lacks one exact active authority route'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_server_service_current_manifest_route_exact';
    END IF;
END;
$automata$;

WITH incompatible AS MATERIALIZED (
    SELECT historical.id AS authority_id
    FROM automata_migration_0053_current_routes AS current_route
    JOIN github_server_service_authorities AS historical
      ON historical.tenant_id = current_route.tenant_id
     AND historical.repository_id = current_route.repository_id
     AND historical.service_scope = current_route.service_scope
     AND historical.state = 'active'
    WHERE NOT (
        ROW(
            historical.tenant_id,
            historical.repository_id,
            historical.provider_connection_id,
            historical.provider_installation_id,
            historical.github_app_id,
            historical.github_app_client_id,
            historical.github_app_jwt_issuer_kind,
            historical.github_repository_id,
            historical.github_repository_name,
            historical.service_scope,
            historical.app_key_spki_sha256
        ) IS NOT DISTINCT FROM ROW(
            current_route.tenant_id,
            current_route.repository_id,
            current_route.provider_connection_id,
            current_route.provider_installation_id,
            current_route.github_app_id,
            current_route.github_app_client_id,
            current_route.github_app_jwt_issuer_kind,
            current_route.github_repository_id,
            current_route.github_repository_name,
            current_route.service_scope,
            current_route.app_key_spki_sha256
        )
        AND (
            historical.configuration_fingerprint
                = current_route.configuration_fingerprint
            OR EXISTS (
                SELECT 1
                FROM automata_migration_0053_compatible_routes AS compatible
                WHERE compatible.service_scope = historical.service_scope
                  AND compatible.configuration_fingerprint
                      = historical.configuration_fingerprint
            )
        )
    )

    UNION

    SELECT historical.id AS authority_id
    FROM automata_migration_0053_manifest_scopes AS manifest
    JOIN github_server_service_authorities AS historical
      ON historical.tenant_id = manifest.tenant_id
     AND historical.repository_id = manifest.repository_id
     AND historical.service_scope = 'private_repository_source_read'
     AND historical.state = 'active'
    WHERE manifest.service_scope = 'checks_write'
      AND manifest.repository_source_authentication = 'anonymous_public'
), database_time AS MATERIALIZED (
    SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
)
INSERT INTO automata_migration_0053_retire_authorities (
    authority_id, transition_at_ms
)
SELECT incompatible.authority_id, database_time.now_ms
FROM incompatible
CROSS JOIN database_time;

-- Migration cannot prove that any nonterminal issuance avoided provider I/O or
-- safely advance the authority's failure budget.  Every issuance must already
-- be terminal and custody-free; otherwise the live lifecycle worker must
-- reconcile it before this migration can proceed.
DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM automata_migration_0053_retire_authorities AS candidate
        JOIN github_server_service_authorities AS authority
          ON authority.id = candidate.authority_id
        LEFT JOIN github_server_service_authority_issuances AS issuance
          ON issuance.authority_id = authority.id
        WHERE authority.state_updated_at_ms > candidate.transition_at_ms
           OR issuance.state_updated_at_ms > candidate.transition_at_ms
    ) THEN
        RAISE EXCEPTION 'incompatible historical GitHub authority has future lifecycle evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_server_service_historical_route_retirement_time';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM automata_migration_0053_retire_authorities AS candidate
        JOIN github_server_service_authority_issuances AS issuance
          ON issuance.authority_id = candidate.authority_id
        WHERE issuance.state NOT IN ('rejected', 'revoked')
           OR issuance.envelope_schema IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'incompatible historical GitHub authority requires live credential reconciliation'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_server_service_historical_route_retirement_safe';
    END IF;
END;
$automata$;

UPDATE github_server_service_authorities AS authority
SET state = 'retiring',
    current_issuance_generation = NULL,
    refresh_issuance_generation = NULL,
    state_updated_at_ms = candidate.transition_at_ms
FROM automata_migration_0053_retire_authorities AS candidate
WHERE authority.id = candidate.authority_id
  AND authority.state = 'active';

UPDATE github_server_service_authorities AS authority
SET state = 'retired',
    retired_at_ms = candidate.transition_at_ms,
    state_updated_at_ms = candidate.transition_at_ms
FROM automata_migration_0053_retire_authorities AS candidate
WHERE authority.id = candidate.authority_id
  AND authority.state = 'retiring'
  AND NOT EXISTS (
      SELECT 1
      FROM github_server_service_authority_issuances AS issuance
      WHERE issuance.authority_id = authority.id
        AND (
            issuance.state NOT IN ('rejected', 'revoked')
            OR issuance.envelope_schema IS NOT NULL
        )
  );

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM automata_migration_0053_retire_authorities AS candidate
        JOIN github_server_service_authorities AS authority
          ON authority.id = candidate.authority_id
        WHERE authority.state <> 'retired'
    ) THEN
        RAISE EXCEPTION 'incompatible historical GitHub authority did not retire atomically'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_server_service_historical_route_retirement_complete';
    END IF;
END;
$automata$;
