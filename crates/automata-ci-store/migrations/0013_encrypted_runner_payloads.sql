-- Runner commands and RPC responses can contain resolved credentials and other
-- execution secrets. Durable retry state therefore stores only authenticated
-- encryption envelopes. Existing plaintext rows cannot be transformed without
-- exposing them to migration machinery, and deleting them here would not be
-- cryptographic erasure. Operators must explicitly drain the retry ledgers or
-- recreate the encrypted storage before applying this migration.

LOCK TABLE runner_command_outbox, runner_rpc_receipts IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM runner_command_outbox LIMIT 1)
        OR EXISTS (SELECT 1 FROM runner_rpc_receipts LIMIT 1)
    THEN
        RAISE EXCEPTION
            'legacy plaintext runner payloads remain; drain retry state or recreate encrypted storage before migration'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_encrypted_payloads_legacy_plaintext_rows';
    END IF;
END;
$automata$;

ALTER TABLE runners
    ADD CONSTRAINT runners_tenant_id_id_unique UNIQUE (tenant_id, id);

ALTER TABLE runner_command_outbox
    DROP CONSTRAINT runner_command_outbox_payload_size,
    DROP COLUMN command_payload,
    ADD COLUMN tenant_id TEXT NOT NULL,
    ADD COLUMN command_plaintext_size_bytes BIGINT NOT NULL,
    ADD COLUMN envelope_schema INTEGER NOT NULL,
    ADD COLUMN wrapping_key_id TEXT NOT NULL,
    ADD COLUMN wrapped_data_key BYTEA NOT NULL,
    ADD COLUMN nonce BYTEA NOT NULL,
    ADD COLUMN ciphertext BYTEA NOT NULL,
    ADD CONSTRAINT runner_command_outbox_tenant_runner
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runners (tenant_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT runner_command_outbox_plaintext_size_range CHECK (
        command_plaintext_size_bytes BETWEEN 1 AND 16777216
    ),
    ADD CONSTRAINT runner_command_outbox_envelope_schema_v1 CHECK (
        envelope_schema = 1
    ),
    ADD CONSTRAINT runner_command_outbox_wrapping_key_id_canonical CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 64
        AND wrapping_key_id ~ '^[a-z0-9][a-z0-9._-]*$'
        AND right(wrapping_key_id, 1) ~ '^[a-z0-9]$'
    ),
    ADD CONSTRAINT runner_command_outbox_wrapped_data_key_size CHECK (
        octet_length(wrapped_data_key) BETWEEN 1 AND 65536
    ),
    ADD CONSTRAINT runner_command_outbox_nonce_size CHECK (
        octet_length(nonce) = 12
    ),
    ADD CONSTRAINT runner_command_outbox_ciphertext_size CHECK (
        octet_length(ciphertext)::NUMERIC = command_plaintext_size_bytes::NUMERIC + 16
        AND octet_length(ciphertext) <= 16777232
    );

ALTER TABLE runner_rpc_receipts
    DROP CONSTRAINT runner_rpc_receipts_response_size,
    DROP COLUMN response_payload,
    ADD COLUMN tenant_id TEXT NOT NULL,
    ADD COLUMN response_plaintext_size_bytes BIGINT NOT NULL,
    ADD COLUMN envelope_schema INTEGER NOT NULL,
    ADD COLUMN wrapping_key_id TEXT NOT NULL,
    ADD COLUMN wrapped_data_key BYTEA NOT NULL,
    ADD COLUMN nonce BYTEA NOT NULL,
    ADD COLUMN ciphertext BYTEA NOT NULL,
    ADD CONSTRAINT runner_rpc_receipts_tenant_runner
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runners (tenant_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT runner_rpc_receipts_plaintext_size_range CHECK (
        response_plaintext_size_bytes BETWEEN 1 AND 16777216
    ),
    ADD CONSTRAINT runner_rpc_receipts_envelope_schema_v1 CHECK (
        envelope_schema = 1
    ),
    ADD CONSTRAINT runner_rpc_receipts_wrapping_key_id_canonical CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 64
        AND wrapping_key_id ~ '^[a-z0-9][a-z0-9._-]*$'
        AND right(wrapping_key_id, 1) ~ '^[a-z0-9]$'
    ),
    ADD CONSTRAINT runner_rpc_receipts_wrapped_data_key_size CHECK (
        octet_length(wrapped_data_key) BETWEEN 1 AND 65536
    ),
    ADD CONSTRAINT runner_rpc_receipts_nonce_size CHECK (
        octet_length(nonce) = 12
    ),
    ADD CONSTRAINT runner_rpc_receipts_ciphertext_size CHECK (
        octet_length(ciphertext)::NUMERIC = response_plaintext_size_bytes::NUMERIC + 16
        AND octet_length(ciphertext) <= 16777232
    );
