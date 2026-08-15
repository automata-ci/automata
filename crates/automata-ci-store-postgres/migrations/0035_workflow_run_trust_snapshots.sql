-- AUTH-02: bind one immutable, canonical trust decision to each workflow run.
--
-- The snapshot is deliberately stored as canonical bytes plus its domain-separated
-- digest. Consumers must rehydrate and validate those bytes; columns are only an
-- indexed/constraint-friendly copy of the envelope metadata.

CREATE TABLE workflow_run_trust_snapshots (
    run_id UUID PRIMARY KEY,
    snapshot_schema SMALLINT NOT NULL,
    policy_revision BIGINT NOT NULL,
    policy_digest BYTEA NOT NULL,
    snapshot_digest BYTEA NOT NULL,
    snapshot_bytes BYTEA NOT NULL,
    media_type TEXT COLLATE "C" NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_run_trust_snapshots_schema_v1
        CHECK (snapshot_schema = 1),
    CONSTRAINT workflow_run_trust_snapshots_policy_revision_positive
        CHECK (policy_revision > 0),
    CONSTRAINT workflow_run_trust_snapshots_policy_digest_sha256
        CHECK (octet_length(policy_digest) = 32),
    CONSTRAINT workflow_run_trust_snapshots_snapshot_digest_sha256
        CHECK (octet_length(snapshot_digest) = 32),
    CONSTRAINT workflow_run_trust_snapshots_snapshot_bytes_bounded
        CHECK (octet_length(snapshot_bytes) BETWEEN 1 AND 32768),
    CONSTRAINT workflow_run_trust_snapshots_media_type_v1
        CHECK (
            media_type =
                'application/vnd.automata.workflow-trust-snapshot.v1+json'
        ),
    CONSTRAINT workflow_run_trust_snapshots_created_at_nonnegative
        CHECK (created_at_ms >= 0),
    CONSTRAINT workflow_run_trust_snapshots_run_fk
        FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX workflow_run_trust_snapshots_run_digest_uq
    ON workflow_run_trust_snapshots (run_id, snapshot_digest);

CREATE FUNCTION automata_reject_workflow_run_trust_snapshot_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'workflow run trust snapshots are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workflow_run_trust_snapshots_immutable';
END;
$$;

CREATE TRIGGER workflow_run_trust_snapshots_reject_update_delete
    BEFORE UPDATE OR DELETE ON workflow_run_trust_snapshots
    FOR EACH ROW
    EXECUTE FUNCTION automata_reject_workflow_run_trust_snapshot_mutation();

CREATE TRIGGER workflow_run_trust_snapshots_reject_truncate
    BEFORE TRUNCATE ON workflow_run_trust_snapshots
    FOR EACH STATEMENT
    EXECUTE FUNCTION automata_reject_workflow_run_trust_snapshot_mutation();
