ALTER TABLE workflow_artifacts
    DROP CONSTRAINT workflow_artifacts_protocol_version,
    ADD CONSTRAINT workflow_artifacts_protocol_version
        CHECK (protocol_version = 7);

COMMENT ON CONSTRAINT workflow_artifacts_protocol_version ON workflow_artifacts IS
    'Accepts the single GitHub Actions artifact protocol version implemented by the results service.';
