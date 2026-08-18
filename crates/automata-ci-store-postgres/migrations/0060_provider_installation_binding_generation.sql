ALTER TABLE workspace_github_repository_selections
    ADD COLUMN installation_binding_generation bigint NOT NULL DEFAULT 1;

ALTER TABLE workspace_github_repository_selections
    ALTER COLUMN installation_binding_generation DROP DEFAULT;

ALTER TABLE workspace_github_repository_selections
    ADD CONSTRAINT workspace_github_repository_installation_binding_generation_positive
    CHECK (installation_binding_generation > 0);

CREATE TABLE workspace_github_repository_installation_bindings (
    workspace_id text NOT NULL,
    provider_repository_id bigint NOT NULL,
    provider_installation_id bigint NOT NULL,
    binding_generation bigint NOT NULL,
    updated_at_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id, provider_repository_id),
    CONSTRAINT workspace_github_repository_installation_bindings_workspace
        FOREIGN KEY (workspace_id)
        REFERENCES workspace_management_bindings(workspace_id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_github_repository_installation_bindings_positive CHECK (
        provider_repository_id > 0
        AND provider_installation_id > 0
        AND binding_generation > 0
        AND updated_at_revision > 0
    )
);

INSERT INTO workspace_github_repository_installation_bindings (
    workspace_id, provider_repository_id, provider_installation_id,
    binding_generation, updated_at_revision
)
SELECT workspace_id, provider_repository_id, provider_installation_id,
       installation_binding_generation, revision
FROM workspace_github_repository_selections;
