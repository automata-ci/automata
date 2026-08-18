ALTER TABLE github_provider_configuration_current
    ADD COLUMN runner_policy_revision bigint NOT NULL DEFAULT 1;

ALTER TABLE github_provider_configuration_current
    ALTER COLUMN runner_policy_revision DROP DEFAULT;

ALTER TABLE github_provider_configuration_current
    ADD CONSTRAINT github_provider_configuration_current_runner_policy_revision_positive
    CHECK (runner_policy_revision > 0);
