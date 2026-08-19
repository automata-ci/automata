ALTER TABLE windows_runner_admissions
    DROP CONSTRAINT windows_runner_admissions_schema;

ALTER TABLE windows_runner_admissions
    ADD CONSTRAINT windows_runner_admissions_schema_known
    CHECK (schema_version IN (1, 2));
