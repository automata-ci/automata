-- Preserve masked diagnostics and explicitly public job outputs without
-- widening readable-secret resources beyond their private audience. Schema 1
-- snapshots retain their immutable blanket-suppression policy; schema 2 uses
-- runner-side value redaction and per-output sensitivity.

LOCK TABLE job_attempts, attempt_log_streams,
    workflow_plan_v2_instance_results,
    workflow_plan_v2_instance_result_claims,
    workflow_plan_v2_instance_result_outputs
    IN ACCESS EXCLUSIVE MODE;

ALTER TABLE job_attempts
    DROP CONSTRAINT job_attempts_exposure_safety,
    DROP CONSTRAINT job_attempts_output_safety_schema,
    ADD CONSTRAINT job_attempts_exposure_safety CHECK (
        (
            output_safety_schema = 1
            AND (
                (
                    secret_exposure_class IN ('secretless', 'capability_only')
                    AND raw_log_disposition = 'persist'
                ) OR (
                    secret_exposure_class = 'readable_secret'
                    AND raw_log_disposition = 'suppress_user_output'
                    AND effective_log_visibility = 'private'
                )
            )
        ) OR (
            output_safety_schema = 2
            AND raw_log_disposition = 'persist'
            AND (
                secret_exposure_class <> 'readable_secret'
                OR effective_log_visibility = 'private'
            )
        )
    ),
    ADD CONSTRAINT job_attempts_output_safety_schema CHECK (
        output_safety_schema IN (1, 2)
    );

ALTER TABLE attempt_log_streams
    DROP CONSTRAINT attempt_log_streams_exposure_safety,
    DROP CONSTRAINT attempt_log_streams_output_safety_schema,
    ADD CONSTRAINT attempt_log_streams_exposure_safety CHECK (
        (
            output_safety_schema = 1
            AND (
                (
                    secret_exposure_class IN ('secretless', 'capability_only')
                    AND raw_log_disposition = 'persist'
                ) OR (
                    secret_exposure_class = 'readable_secret'
                    AND raw_log_disposition = 'suppress_user_output'
                    AND effective_visibility = 'private'
                )
            )
        ) OR (
            output_safety_schema = 2
            AND raw_log_disposition = 'persist'
            AND (
                secret_exposure_class <> 'readable_secret'
                OR effective_visibility = 'private'
            )
        )
    ),
    ADD CONSTRAINT attempt_log_streams_output_safety_schema CHECK (
        output_safety_schema IN (1, 2)
    );

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_instance_result_output()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_instance_results AS result
        JOIN workflow_plan_v2_instance_result_claims AS claim
          ON claim.instance_id = result.instance_id
        WHERE result.instance_id = NEW.instance_id
          AND claim.state = 'projecting'
          AND result.claim_owner_id = claim.owner_id
          AND result.claim_generation = claim.generation
          AND result.claim_started_at_ms = claim.claimed_at_ms
          AND result.claim_expires_at_ms = claim.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 output lacks a live instance-result fence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;
