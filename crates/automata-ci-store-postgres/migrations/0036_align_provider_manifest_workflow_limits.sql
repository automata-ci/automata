-- Preserve historical provider-manifest evidence while admitting the current
-- 500-KiB workflow-source policy. Manifest rows and their digest-bound foreign
-- keys remain immutable; only the closed set accepted by the table changes.
ALTER TABLE ONLY github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_archive_limits_compat CHECK (
        archive_max_compressed_bytes = 268435456
        AND archive_max_decompressed_bytes = 2147483648
        AND archive_max_entries = 100000
        AND archive_max_expanded_bytes = 1073741824
        AND archive_max_entry_path_bytes = 4096
        AND archive_max_workflows = 256
        AND workflow_max_bytes IN (512000, 1048576)
    ) NOT VALID;

ALTER TABLE ONLY github_provider_manifest_revisions
    VALIDATE CONSTRAINT github_provider_manifest_revisions_archive_limits_compat;

ALTER TABLE ONLY github_provider_manifest_revisions
    DROP CONSTRAINT github_provider_manifest_revisions_archive_limits;

ALTER TABLE ONLY github_provider_manifest_revisions
    RENAME CONSTRAINT github_provider_manifest_revisions_archive_limits_compat
    TO github_provider_manifest_revisions_archive_limits;
