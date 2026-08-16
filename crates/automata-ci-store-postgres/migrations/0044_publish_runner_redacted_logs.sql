-- Runner log segments contain only bytes produced after the mandatory secret
-- masker. Publication schema 2 therefore applies the repository's requested
-- log audience exactly; readable runtime authority still narrows artifacts.

ALTER TABLE workflow_runs DISABLE TRIGGER USER;
ALTER TABLE job_attempts DISABLE TRIGGER USER;
ALTER TABLE attempt_log_streams DISABLE TRIGGER USER;
ALTER TABLE workflow_artifacts DISABLE TRIGGER USER;

ALTER TABLE workflow_runs
    DROP CONSTRAINT workflow_runs_publication_safety_schema;
ALTER TABLE job_attempts
    DROP CONSTRAINT job_attempts_exposure_safety,
    DROP CONSTRAINT job_attempts_output_safety_reason_code,
    DROP CONSTRAINT job_attempts_output_safety_schema;
ALTER TABLE attempt_log_streams
    DROP CONSTRAINT attempt_log_streams_exposure_safety,
    DROP CONSTRAINT attempt_log_streams_output_safety_reason_code,
    DROP CONSTRAINT attempt_log_streams_output_safety_schema;
ALTER TABLE workflow_artifacts
    DROP CONSTRAINT workflow_artifacts_publication_safety_schema;

ALTER TABLE workflow_runs
    ALTER COLUMN publication_safety_schema SET DEFAULT 2;
ALTER TABLE job_attempts
    ALTER COLUMN output_safety_schema SET DEFAULT 2;
ALTER TABLE attempt_log_streams
    ALTER COLUMN output_safety_schema SET DEFAULT 2;
ALTER TABLE workflow_artifacts
    ALTER COLUMN publication_safety_schema SET DEFAULT 2;

UPDATE workflow_runs
SET publication_safety_schema = 2;

UPDATE job_attempts
SET effective_log_visibility = requested_log_visibility,
    output_safety_reason = 'repository_policy',
    output_safety_schema = 2;

UPDATE attempt_log_streams
SET effective_visibility = requested_visibility,
    output_safety_reason = 'repository_policy',
    output_safety_schema = 2;

UPDATE workflow_artifacts
SET publication_safety_schema = 2;

ALTER TABLE workflow_runs
    ADD CONSTRAINT workflow_runs_publication_safety_schema
    CHECK (publication_safety_schema = 2);
ALTER TABLE job_attempts
    ADD CONSTRAINT job_attempts_exposure_safety
    CHECK (
        output_safety_schema = 2
        AND raw_log_disposition = 'persist'
        AND effective_log_visibility = requested_log_visibility
    ),
    ADD CONSTRAINT job_attempts_output_safety_reason_code
    CHECK (output_safety_reason = 'repository_policy'),
    ADD CONSTRAINT job_attempts_output_safety_schema
    CHECK (output_safety_schema = 2);
ALTER TABLE attempt_log_streams
    ADD CONSTRAINT attempt_log_streams_exposure_safety
    CHECK (
        output_safety_schema = 2
        AND raw_log_disposition = 'persist'
        AND effective_visibility = requested_visibility
    ),
    ADD CONSTRAINT attempt_log_streams_output_safety_reason_code
    CHECK (output_safety_reason = 'repository_policy'),
    ADD CONSTRAINT attempt_log_streams_output_safety_schema
    CHECK (output_safety_schema = 2);
ALTER TABLE workflow_artifacts
    ADD CONSTRAINT workflow_artifacts_publication_safety_schema
    CHECK (publication_safety_schema = 2);

ALTER TABLE workflow_runs ENABLE TRIGGER USER;
ALTER TABLE job_attempts ENABLE TRIGGER USER;
ALTER TABLE attempt_log_streams ENABLE TRIGGER USER;
ALTER TABLE workflow_artifacts ENABLE TRIGGER USER;
