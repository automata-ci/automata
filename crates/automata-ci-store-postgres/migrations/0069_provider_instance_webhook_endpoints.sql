-- Advance provider webhook endpoints from repository-connection ownership to
-- provider-instance ownership without rewriting the deployed 0053/0056
-- lineage. Deliveries retain an exact direct connection-revision binding.

ALTER TABLE provider_deliveries
    DROP CONSTRAINT provider_deliveries_endpoint_id_endpoint_revision_provider_fkey;

ALTER TABLE provider_webhook_endpoint_revisions
    DROP CONSTRAINT provider_webhook_endpoint_rev_connection_id_connection_rev_fkey,
    DROP CONSTRAINT provider_webhook_endpoint_rev_endpoint_id_revision_provider_key,
    ADD UNIQUE (
        endpoint_id, revision, provider_type, provider_instance_id,
        provider_revision
    );

ALTER TABLE provider_deliveries
    ADD FOREIGN KEY (
        endpoint_id, endpoint_revision, provider_type,
        provider_instance_id, provider_revision
    ) REFERENCES provider_webhook_endpoint_revisions (
        endpoint_id, revision, provider_type,
        provider_instance_id, provider_revision
    ) ON DELETE RESTRICT,
    ADD FOREIGN KEY (
        connection_id, connection_revision,
        provider_instance_id, provider_revision
    ) REFERENCES provider_connection_revisions (
        connection_id, revision, provider_instance_id, provider_revision
    ) ON DELETE RESTRICT;

ALTER TABLE provider_webhook_endpoint_revisions
    DROP COLUMN connection_id,
    DROP COLUMN connection_revision;
