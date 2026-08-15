ALTER TABLE logical_workflow_activation_publications
    ADD COLUMN scheduling_policy_schema smallint NOT NULL,
    ADD COLUMN requested_max_parallel bigint,
    ADD COLUMN effective_max_parallel integer NOT NULL,
    ADD CONSTRAINT logical_workflow_activation_publications_scheduling_schema_exact
        CHECK (scheduling_policy_schema = 1),
    ADD CONSTRAINT logical_workflow_activation_publications_requested_parallel_positive
        CHECK (
            requested_max_parallel IS NULL
            OR requested_max_parallel BETWEEN 1 AND 4294967295
        ),
    ADD CONSTRAINT logical_workflow_activation_publications_effective_parallel_shape
        CHECK (
            (instance_count = 0 AND effective_max_parallel = 0)
            OR (
                instance_count > 0
                AND effective_max_parallel BETWEEN 1 AND instance_count
            )
        ),
    ADD CONSTRAINT logical_workflow_activation_publications_parallel_resolution_exact
        CHECK (
            (
                requested_max_parallel IS NULL
                AND effective_max_parallel = instance_count
            )
            OR (
                requested_max_parallel IS NOT NULL
                AND effective_max_parallel = LEAST(requested_max_parallel, instance_count)
            )
        );
