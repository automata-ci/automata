CREATE UNIQUE INDEX provider_result_subjects_workflow_run
    ON provider_result_subjects (run_id)
    WHERE subject_kind = 'workflow-run';
