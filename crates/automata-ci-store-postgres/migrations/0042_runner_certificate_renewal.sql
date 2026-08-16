-- One durable successor and replay receipt are permitted for each presented leaf.
ALTER TABLE runner_machine_certificates
    ADD CONSTRAINT runner_machine_certificates_runner_leaf_unique
    UNIQUE (runner_id, leaf_sha256);

CREATE TABLE runner_certificate_renewal_receipts (
    operation_id uuid PRIMARY KEY,
    runner_id uuid NOT NULL,
    presented_leaf_sha256 bytea NOT NULL,
    request_sha256 bytea NOT NULL,
    renewed_leaf_sha256 bytea NOT NULL,
    response bytea NOT NULL,
    renewed_expires_at_seconds bigint NOT NULL,
    created_at_ms bigint NOT NULL,
    audit_event_id uuid NOT NULL,
    CONSTRAINT runner_certificate_renewal_receipts_presented_digest
        CHECK (octet_length(presented_leaf_sha256) = 32),
    CONSTRAINT runner_certificate_renewal_receipts_request_digest
        CHECK (octet_length(request_sha256) = 32),
    CONSTRAINT runner_certificate_renewal_receipts_renewed_digest
        CHECK (octet_length(renewed_leaf_sha256) = 32),
    CONSTRAINT runner_certificate_renewal_receipts_distinct_certificates
        CHECK (presented_leaf_sha256 <> renewed_leaf_sha256),
    CONSTRAINT runner_certificate_renewal_receipts_response_bound
        CHECK (octet_length(response) BETWEEN 1 AND 524288),
    CONSTRAINT runner_certificate_renewal_receipts_expiration_positive
        CHECK (renewed_expires_at_seconds > 0),
    CONSTRAINT runner_certificate_renewal_receipts_created_positive
        CHECK (created_at_ms > 0),
    CONSTRAINT runner_certificate_renewal_receipts_presented_unique
        UNIQUE (presented_leaf_sha256),
    CONSTRAINT runner_certificate_renewal_receipts_renewed_unique
        UNIQUE (renewed_leaf_sha256),
    CONSTRAINT runner_certificate_renewal_receipts_runner_presented_fkey
        FOREIGN KEY (runner_id, presented_leaf_sha256)
        REFERENCES runner_machine_certificates (runner_id, leaf_sha256)
        ON DELETE RESTRICT,
    CONSTRAINT runner_certificate_renewal_receipts_runner_renewed_fkey
        FOREIGN KEY (runner_id, renewed_leaf_sha256)
        REFERENCES runner_machine_certificates (runner_id, leaf_sha256)
        ON DELETE RESTRICT,
    CONSTRAINT runner_certificate_renewal_receipts_runner_fkey
        FOREIGN KEY (runner_id) REFERENCES runners (id) ON DELETE RESTRICT,
    CONSTRAINT runner_certificate_renewal_receipts_audit_fkey
        FOREIGN KEY (audit_event_id) REFERENCES security_audit_events (event_id)
        ON DELETE RESTRICT
);

CREATE INDEX runner_certificate_renewal_receipts_runner_created
    ON runner_certificate_renewal_receipts (runner_id, created_at_ms);

CREATE FUNCTION automata_reject_runner_certificate_renewal_receipt_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'runner certificate renewal receipts are immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'runner_certificate_renewal_receipts_immutable';
END;
$$;

CREATE FUNCTION automata_guard_runner_certificate_renewal_receipt_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    presented_expires_at_seconds bigint;
BEGIN
    SELECT certificate.expires_at_seconds
      INTO presented_expires_at_seconds
      FROM runner_machine_certificates AS certificate
     WHERE certificate.runner_id = OLD.runner_id
       AND certificate.leaf_sha256 = OLD.presented_leaf_sha256;

    IF presented_expires_at_seconds IS NULL
       OR presented_expires_at_seconds > floor(extract(epoch FROM clock_timestamp())) THEN
        RAISE EXCEPTION 'live runner certificate renewal receipts are immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_certificate_renewal_receipts_live_delete';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER runner_certificate_renewal_receipts_no_update
    BEFORE UPDATE ON runner_certificate_renewal_receipts
    FOR EACH ROW EXECUTE FUNCTION automata_reject_runner_certificate_renewal_receipt_update();

CREATE TRIGGER runner_certificate_renewal_receipts_guard_delete
    BEFORE DELETE ON runner_certificate_renewal_receipts
    FOR EACH ROW EXECUTE FUNCTION automata_guard_runner_certificate_renewal_receipt_delete();

CREATE TRIGGER runner_certificate_renewal_receipts_no_truncate
    BEFORE TRUNCATE ON runner_certificate_renewal_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_runner_certificate_renewal_receipt_update();
