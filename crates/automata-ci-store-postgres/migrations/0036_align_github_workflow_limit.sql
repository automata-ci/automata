ALTER TABLE github_provider_manifest_revisions
    DROP CONSTRAINT github_provider_manifest_revisions_archive_limits,
    ADD CONSTRAINT github_provider_manifest_revisions_archive_limits CHECK (
        archive_max_compressed_bytes = 268435456
        AND archive_max_decompressed_bytes = 2147483648
        AND archive_max_entries = 100000
        AND archive_max_expanded_bytes = 1073741824
        AND archive_max_entry_path_bytes = 4096
        AND archive_max_workflows = 256
        AND workflow_max_bytes = 512000
    );
