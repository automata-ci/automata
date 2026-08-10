-- Human-readable workflow-run metadata used by tenant-scoped dashboard reads.
-- Every projection column remains nullable so runs admitted before this
-- migration keep their exact historical meaning instead of receiving guessed
-- values during the upgrade.

ALTER TABLE workflow_runs
    ADD COLUMN workflow_name TEXT,
    ADD COLUMN git_ref TEXT,
    ADD COLUMN actor TEXT,
    ADD COLUMN display_title TEXT,
    ADD COLUMN commit_subject TEXT,
    ADD CONSTRAINT workflow_runs_workflow_name_shape CHECK (
        workflow_name IS NULL OR (
            octet_length(workflow_name) BETWEEN 1 AND 1024
            AND workflow_name !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT workflow_runs_git_ref_shape CHECK (
        git_ref IS NULL OR (
            octet_length(git_ref) BETWEEN 6 AND 1024
            AND git_ref LIKE 'refs/%'
            AND git_ref !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT workflow_runs_actor_shape CHECK (
        actor IS NULL OR (
            octet_length(actor) BETWEEN 1 AND 1024
            AND actor !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT workflow_runs_display_title_shape CHECK (
        display_title IS NULL OR (
            octet_length(display_title) BETWEEN 1 AND 1024
            AND display_title !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT workflow_runs_commit_subject_shape CHECK (
        commit_subject IS NULL OR (
            octet_length(commit_subject) BETWEEN 1 AND 1024
            AND commit_subject !~ '[[:cntrl:]]'
        )
    );

CREATE INDEX workflow_runs_repository_created
    ON workflow_runs (repository_id, created_at_ms DESC, id DESC);

CREATE INDEX workflow_runs_repository_workflow_created
    ON workflow_runs (
        repository_id, workflow_id, created_at_ms DESC, id DESC
    );

CREATE INDEX workflow_runs_repository_status_created
    ON workflow_runs (repository_id, status, created_at_ms DESC, id DESC);

CREATE INDEX workflow_runs_repository_ref_created
    ON workflow_runs (repository_id, git_ref, created_at_ms DESC, id DESC)
    WHERE git_ref IS NOT NULL;
