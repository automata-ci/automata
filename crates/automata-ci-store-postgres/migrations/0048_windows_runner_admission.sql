-- Windows runners may be registered only from a server-verified, broker-signed
-- admission whose nonce and image-promotion rollback coordinates are consumed
-- atomically with the one-time enrollment token.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM runners
        WHERE capabilities #>> '{platform,operating_system,kind}' = 'windows'
    ) THEN
        RAISE EXCEPTION 'existing Windows runners must be removed and re-enrolled through broker admission before migration 0048'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'windows_runner_admission_upgrade_requires_reenrollment';
    END IF;
END
$$;

CREATE TABLE windows_runner_admission_nonces (
    nonce bytea PRIMARY KEY,
    enrollment_id uuid NOT NULL,
    issuer_key_id text NOT NULL,
    envelope_sha256 bytea NOT NULL,
    reserved_at_ms bigint NOT NULL,
    CONSTRAINT windows_runner_admission_nonces_digest CHECK (
        octet_length(nonce) = 32
        AND nonce <> decode(repeat('00', 32), 'hex')
        AND octet_length(envelope_sha256) = 32
        AND envelope_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    CONSTRAINT windows_runner_admission_nonces_issuer CHECK (
        issuer_key_id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'
    ),
    CONSTRAINT windows_runner_admission_nonces_time CHECK (reserved_at_ms >= 0),
    CONSTRAINT windows_runner_admission_nonces_envelope_unique UNIQUE (envelope_sha256),
    CONSTRAINT windows_runner_admission_nonces_exact_unique UNIQUE (
        nonce,enrollment_id,issuer_key_id,envelope_sha256
    ),
    CONSTRAINT windows_runner_admission_nonces_enrollment_fkey FOREIGN KEY (enrollment_id)
        REFERENCES runner_enrollment_tokens(id) ON DELETE RESTRICT
);

CREATE TABLE windows_image_promotion_high_water (
    trust_bundle_id text NOT NULL,
    promotion_key_id text NOT NULL,
    promotion_trust_bundle_sha256 bytea NOT NULL,
    promotion_public_key_sha256 bytea NOT NULL,
    promotion_serial bigint NOT NULL,
    revocation_generation bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT windows_image_promotion_high_water_pkey PRIMARY KEY (
        trust_bundle_id,promotion_key_id
    ),
    CONSTRAINT windows_image_promotion_high_water_exact_unique UNIQUE (
        trust_bundle_id,promotion_key_id,
        promotion_trust_bundle_sha256,promotion_public_key_sha256
    ),
    CONSTRAINT windows_image_promotion_high_water_ids CHECK (
        trust_bundle_id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'
        AND promotion_key_id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'
    ),
    CONSTRAINT windows_image_promotion_high_water_digests CHECK (
        octet_length(promotion_trust_bundle_sha256) = 32
        AND promotion_trust_bundle_sha256 <> decode(repeat('00', 32), 'hex')
        AND octet_length(promotion_public_key_sha256) = 32
        AND promotion_public_key_sha256 <> decode(repeat('00', 32), 'hex')
    ),
    CONSTRAINT windows_image_promotion_high_water_values CHECK (
        promotion_serial > 0 AND revocation_generation > 0 AND updated_at_ms >= 0
    )
);

CREATE FUNCTION automata_windows_image_promotion_high_water_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.trust_bundle_id <> OLD.trust_bundle_id
       OR NEW.promotion_key_id <> OLD.promotion_key_id
       OR NEW.promotion_trust_bundle_sha256 <> OLD.promotion_trust_bundle_sha256
       OR NEW.promotion_public_key_sha256 <> OLD.promotion_public_key_sha256
       OR NEW.promotion_serial < OLD.promotion_serial
       OR NEW.revocation_generation < OLD.revocation_generation
       OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'Windows image promotion high-water state is immutable or monotonic'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'windows_image_promotion_high_water_monotonic';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER windows_image_promotion_high_water_guard
BEFORE UPDATE OR DELETE ON windows_image_promotion_high_water
FOR EACH ROW EXECUTE FUNCTION automata_windows_image_promotion_high_water_guard();

CREATE FUNCTION automata_windows_admission_truncate_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Windows runner admission security state cannot be truncated'
        USING ERRCODE = '23514',
              CONSTRAINT = 'windows_runner_admission_truncate_forbidden';
END
$$;

CREATE TRIGGER windows_image_promotion_high_water_no_truncate
BEFORE TRUNCATE ON windows_image_promotion_high_water
FOR EACH STATEMENT EXECUTE FUNCTION automata_windows_admission_truncate_guard();

ALTER TABLE runner_enrollment_tokens
    ADD CONSTRAINT runner_enrollment_tokens_windows_binding_unique UNIQUE (
        id,tenant_id,consumed_runner_id,redeem_operation_id,redeem_request_sha256
    );

CREATE TABLE windows_runner_admissions (
    enrollment_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    runner_id uuid NOT NULL UNIQUE,
    operation_id uuid NOT NULL,
    request_sha256 bytea NOT NULL,
    schema_version smallint NOT NULL,
    issuer_key_id text NOT NULL,
    nonce bytea NOT NULL,
    envelope_sha256 bytea NOT NULL UNIQUE,
    signed_payload bytea NOT NULL,
    authenticator bytea NOT NULL,
    broker_host_id text NOT NULL,
    sandbox_provider_id text NOT NULL,
    control_origin text NOT NULL,
    enrollment_origin text NOT NULL,
    runner_name_sha256 bytea NOT NULL,
    enrollment_token_sha256 bytea NOT NULL,
    csr_sha256 bytea NOT NULL,
    request_binding_sha256 bytea NOT NULL,
    environment_profile_id text NOT NULL,
    environment_profile_sha256 bytea NOT NULL,
    image_reference text NOT NULL,
    image_sha256 bytea NOT NULL,
    probe_contract_sha256 bytea NOT NULL,
    sealed_action_trees boolean NOT NULL,
    network_disabled boolean NOT NULL,
    promotion_trust_bundle_id text NOT NULL,
    promotion_key_id text NOT NULL,
    promotion_payload_sha256 bytea NOT NULL,
    promotion_envelope_sha256 bytea NOT NULL,
    promotion_serial bigint NOT NULL,
    revocation_generation bigint NOT NULL,
    promotion_issued_at_ms bigint NOT NULL,
    promotion_expires_at_ms bigint NOT NULL,
    receipt_issued_at_ms bigint NOT NULL,
    receipt_expires_at_ms bigint NOT NULL,
    capabilities jsonb NOT NULL,
    capabilities_sha256 bytea NOT NULL,
    custody_handle_sha256 bytea NOT NULL,
    completion_nonce_sha256 bytea NOT NULL,
    broker_attestation_sha256 bytea NOT NULL,
    host_input_attestation_sha256 bytea NOT NULL,
    image_attestation_sha256 bytea NOT NULL,
    network_attestation_sha256 bytea NOT NULL,
    profile_contract_sha256 bytea NOT NULL,
    authority_attestation_sha256 bytea NOT NULL,
    promotion_trust_bundle_sha256 bytea NOT NULL,
    promotion_public_key_sha256 bytea NOT NULL,
    cleanup_receipt_sha256 bytea NOT NULL,
    admitted_at_ms bigint NOT NULL,
    CONSTRAINT windows_runner_admissions_schema CHECK (schema_version = 1),
    CONSTRAINT windows_runner_admissions_ids CHECK (
        runner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND operation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND issuer_key_id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'
        AND broker_host_id ~ '^[0-9a-f]{64}$'
        AND sandbox_provider_id = 'windows-hyperv'
        AND promotion_trust_bundle_id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'
        AND promotion_key_id ~ '^[a-z0-9][a-z0-9._-]{2,127}$'
        AND octet_length(environment_profile_id) BETWEEN 3 AND 128
        AND environment_profile_id ~ '^[a-z]([a-z0-9-]*[a-z0-9])?(\.[a-z]([a-z0-9-]*[a-z0-9])?)*/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'
    ),
    CONSTRAINT windows_runner_admissions_origins CHECK (
        octet_length(control_origin) BETWEEN 1 AND 2048
        AND control_origin !~ '[[:cntrl:]]'
        AND octet_length(enrollment_origin) BETWEEN 1 AND 2048
        AND enrollment_origin !~ '[[:cntrl:]]'
    ),
    CONSTRAINT windows_runner_admissions_image CHECK (
        octet_length(image_reference) BETWEEN 1 AND 2048
        AND image_reference !~ '[[:cntrl:]]'
        AND image_reference LIKE '%@sha256:' || encode(image_sha256, 'hex')
    ),
    CONSTRAINT windows_runner_admissions_payload CHECK (
        octet_length(signed_payload) BETWEEN 1 AND 65536
        AND octet_length(authenticator) = 64
    ),
    CONSTRAINT windows_runner_admissions_windows_only CHECK (
        jsonb_typeof(capabilities) = 'object'
        AND capabilities #>> '{runner_id}' = runner_id::text
        AND capabilities #>> '{platform,operating_system,kind}' = 'windows'
        AND capabilities #>> '{sandbox,maximum_isolation}' = 'virtual_machine'
        AND jsonb_typeof(capabilities #> '{sandbox,features}') = 'array'
        AND capabilities #> '{sandbox,features}' ? 'automata.core/windows-hyperv-container@v1'
        AND jsonb_typeof(capabilities -> 'environment_profiles') = 'array'
        AND jsonb_array_length(capabilities -> 'environment_profiles') = 1
        AND capabilities #>> '{environment_profiles,0,id}' = environment_profile_id
        AND capabilities #>> '{environment_profiles,0,digest}' = encode(environment_profile_sha256, 'hex')
        AND jsonb_typeof(capabilities -> 'features') = 'array'
        AND NOT (capabilities -> 'features' ? 'automata.core/local-actions@v1')
        AND (capabilities -> 'features' ? 'automata.core/javascript-actions@v1') =
            (capabilities -> 'features' ?| ARRAY[
                'automata.core/node12-actions@v1',
                'automata.core/node16-actions@v1',
                'automata.core/node20-actions@v1',
                'automata.core/node24-actions@v1'
            ])
        AND (
            NOT (capabilities -> 'features' ?| ARRAY[
                'automata.core/javascript-actions@v1',
                'automata.core/node12-actions@v1',
                'automata.core/node16-actions@v1',
                'automata.core/node20-actions@v1',
                'automata.core/node24-actions@v1',
                'automata.core/composite-actions@v1',
                'automata.core/repository-actions@v1'
            ])
            OR capabilities -> 'features' ? 'automata.core/repository-actions@v1'
        )
        AND (
            sealed_action_trees
            OR NOT (capabilities -> 'features' ?| ARRAY[
                'automata.core/javascript-actions@v1',
                'automata.core/node12-actions@v1',
                'automata.core/node16-actions@v1',
                'automata.core/node20-actions@v1',
                'automata.core/node24-actions@v1',
                'automata.core/composite-actions@v1',
                'automata.core/repository-actions@v1'
            ])
        )
        AND network_disabled
    ),
    CONSTRAINT windows_runner_admissions_generations CHECK (
        promotion_serial > 0 AND revocation_generation > 0
    ),
    CONSTRAINT windows_runner_admissions_times CHECK (
        promotion_issued_at_ms > 0
        AND promotion_expires_at_ms > promotion_issued_at_ms
        AND promotion_expires_at_ms - promotion_issued_at_ms <= 604800000
        AND receipt_issued_at_ms > 0
        AND receipt_expires_at_ms > receipt_issued_at_ms
        AND receipt_expires_at_ms - receipt_issued_at_ms <= 900000
        AND admitted_at_ms >= receipt_issued_at_ms
        AND admitted_at_ms < receipt_expires_at_ms
        AND admitted_at_ms >= promotion_issued_at_ms
        AND admitted_at_ms < promotion_expires_at_ms
    ),
    CONSTRAINT windows_runner_admissions_digests CHECK (
        octet_length(request_sha256) = 32
        AND octet_length(nonce) = 32
        AND octet_length(envelope_sha256) = 32
        AND octet_length(runner_name_sha256) = 32
        AND octet_length(enrollment_token_sha256) = 32
        AND octet_length(csr_sha256) = 32
        AND octet_length(request_binding_sha256) = 32
        AND octet_length(environment_profile_sha256) = 32
        AND octet_length(image_sha256) = 32
        AND octet_length(probe_contract_sha256) = 32
        AND octet_length(promotion_payload_sha256) = 32
        AND octet_length(promotion_envelope_sha256) = 32
        AND octet_length(capabilities_sha256) = 32
        AND octet_length(custody_handle_sha256) = 32
        AND octet_length(completion_nonce_sha256) = 32
        AND octet_length(broker_attestation_sha256) = 32
        AND octet_length(host_input_attestation_sha256) = 32
        AND octet_length(image_attestation_sha256) = 32
        AND octet_length(network_attestation_sha256) = 32
        AND octet_length(profile_contract_sha256) = 32
        AND octet_length(authority_attestation_sha256) = 32
        AND octet_length(promotion_trust_bundle_sha256) = 32
        AND octet_length(promotion_public_key_sha256) = 32
        AND octet_length(cleanup_receipt_sha256) = 32
        AND NOT (
            decode(repeat('00', 32), 'hex') = ANY (ARRAY[
                request_sha256,nonce,envelope_sha256,runner_name_sha256,
                enrollment_token_sha256,csr_sha256,request_binding_sha256,
                environment_profile_sha256,image_sha256,probe_contract_sha256,
                promotion_payload_sha256,promotion_envelope_sha256,
                capabilities_sha256,custody_handle_sha256,completion_nonce_sha256,
                broker_attestation_sha256,host_input_attestation_sha256,
                image_attestation_sha256,network_attestation_sha256,
                profile_contract_sha256,authority_attestation_sha256,
                promotion_trust_bundle_sha256,promotion_public_key_sha256,
                cleanup_receipt_sha256
            ])
        )
    ),
    CONSTRAINT windows_runner_admissions_token_binding_fkey FOREIGN KEY (
        enrollment_id,tenant_id,runner_id,operation_id,request_sha256
    ) REFERENCES runner_enrollment_tokens (
        id,tenant_id,consumed_runner_id,redeem_operation_id,redeem_request_sha256
    ) ON DELETE RESTRICT,
    CONSTRAINT windows_runner_admissions_nonce_fkey FOREIGN KEY (
        nonce,enrollment_id,issuer_key_id,envelope_sha256
    ) REFERENCES windows_runner_admission_nonces (
        nonce,enrollment_id,issuer_key_id,envelope_sha256
    ) ON DELETE RESTRICT,
    CONSTRAINT windows_runner_admissions_promotion_fkey FOREIGN KEY (
        promotion_trust_bundle_id,promotion_key_id,
        promotion_trust_bundle_sha256,promotion_public_key_sha256
    ) REFERENCES windows_image_promotion_high_water (
        trust_bundle_id,promotion_key_id,
        promotion_trust_bundle_sha256,promotion_public_key_sha256
    ) ON DELETE RESTRICT
);

CREATE FUNCTION automata_windows_runner_admission_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_promotion_serial bigint;
    current_revocation_generation bigint;
    registered_capabilities jsonb;
    database_now_ms bigint;
BEGIN
    -- Lock the rollback floor before the runner so every admission path uses
    -- the same order as enrollment. Sample the database clock only after both
    -- potentially blocking reads have returned.
    SELECT high_water.promotion_serial, high_water.revocation_generation
    INTO current_promotion_serial, current_revocation_generation
    FROM windows_image_promotion_high_water AS high_water
    WHERE high_water.trust_bundle_id = NEW.promotion_trust_bundle_id
      AND high_water.promotion_key_id = NEW.promotion_key_id
      AND high_water.promotion_trust_bundle_sha256 = NEW.promotion_trust_bundle_sha256
      AND high_water.promotion_public_key_sha256 = NEW.promotion_public_key_sha256
    FOR SHARE;

    IF NOT FOUND
       OR current_promotion_serial <> NEW.promotion_serial
       OR current_revocation_generation <> NEW.revocation_generation THEN
        RAISE EXCEPTION 'Windows runner admission does not use the current image promotion floor'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'windows_runner_admission_current_promotion';
    END IF;

    SELECT runner.capabilities
    INTO registered_capabilities
    FROM runners AS runner
    WHERE runner.id = NEW.runner_id
    FOR SHARE;

    IF NOT FOUND
       OR registered_capabilities IS DISTINCT FROM NEW.capabilities
       OR registered_capabilities #>> '{platform,operating_system,kind}' <> 'windows' THEN
        RAISE EXCEPTION 'Windows runner admission does not match one registered Windows runner'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'windows_runner_admission_registered_capabilities';
    END IF;

    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF NEW.receipt_issued_at_ms > database_now_ms
       OR database_now_ms >= NEW.receipt_expires_at_ms
       OR NEW.promotion_issued_at_ms > database_now_ms
       OR database_now_ms >= NEW.promotion_expires_at_ms
       OR NEW.admitted_at_ms > database_now_ms
       OR database_now_ms - NEW.admitted_at_ms > 60000 THEN
        RAISE EXCEPTION 'Windows runner admission is not fresh after admission locks'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'windows_runner_admission_database_freshness';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER windows_runner_admission_insert_guard
BEFORE INSERT ON windows_runner_admissions
FOR EACH ROW EXECUTE FUNCTION automata_windows_runner_admission_insert_guard();

CREATE FUNCTION automata_windows_runner_admission_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Windows runner admission evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'windows_runner_admission_immutable';
END
$$;

CREATE TRIGGER windows_runner_admission_nonce_immutable
BEFORE UPDATE OR DELETE ON windows_runner_admission_nonces
FOR EACH ROW EXECUTE FUNCTION automata_windows_runner_admission_immutable();

CREATE TRIGGER windows_runner_admission_immutable
BEFORE UPDATE OR DELETE ON windows_runner_admissions
FOR EACH ROW EXECUTE FUNCTION automata_windows_runner_admission_immutable();

CREATE TRIGGER windows_runner_admission_nonce_no_truncate
BEFORE TRUNCATE ON windows_runner_admission_nonces
FOR EACH STATEMENT EXECUTE FUNCTION automata_windows_admission_truncate_guard();

CREATE TRIGGER windows_runner_admission_no_truncate
BEFORE TRUNCATE ON windows_runner_admissions
FOR EACH STATEMENT EXECUTE FUNCTION automata_windows_admission_truncate_guard();

CREATE FUNCTION automata_require_windows_runner_admission()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    admitted_capabilities jsonb;
    is_windows boolean;
BEGIN
    is_windows := NEW.capabilities #>> '{platform,operating_system,kind}' = 'windows';
    SELECT admission.capabilities
    INTO admitted_capabilities
    FROM windows_runner_admissions AS admission
    WHERE admission.runner_id = NEW.id;

    IF is_windows AND (admitted_capabilities IS NULL OR admitted_capabilities <> NEW.capabilities) THEN
        RAISE EXCEPTION 'Windows runner lacks exact broker admission'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'windows_runner_requires_exact_admission';
    END IF;
    IF NOT is_windows AND admitted_capabilities IS NOT NULL THEN
        RAISE EXCEPTION 'non-Windows runner cannot carry Windows admission'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'windows_runner_admission_platform_mismatch';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER require_windows_runner_admission
AFTER INSERT OR UPDATE OF capabilities ON runners
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_require_windows_runner_admission();
