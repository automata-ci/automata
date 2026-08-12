ALTER TABLE github_provider_manifest_revisions
    DROP CONSTRAINT github_provider_manifest_revisions_selector_exact,
    ADD CONSTRAINT github_provider_manifest_revisions_selector_exact CHECK (
        workflow_path ~ '^\.ci/workflows/[^/]+\.ya?ml$'
        AND workflow_path !~ '[[:cntrl:]\\]'
        AND check_subject_key = workflow_path
        AND event_name = 'push'
        AND git_ref = 'refs/heads/main'
    );
