ALTER TABLE github_provider_configuration_current
    ADD COLUMN app_private_key_envelope_revision bigint,
    ADD COLUMN webhook_secret_envelope_revision bigint;

UPDATE github_provider_configuration_current
SET app_private_key_envelope_revision = revision,
    webhook_secret_envelope_revision = revision;

ALTER TABLE github_provider_configuration_current
    ALTER COLUMN app_private_key_envelope_revision SET NOT NULL,
    ALTER COLUMN webhook_secret_envelope_revision SET NOT NULL,
    ADD CONSTRAINT github_provider_configuration_current_envelope_revisions_positive CHECK (
        app_private_key_envelope_revision > 0
        AND webhook_secret_envelope_revision > 0
    );
