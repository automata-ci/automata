ALTER TABLE runner_operation_receipts
    DROP CONSTRAINT runner_operation_receipts_outcome,
    DROP CONSTRAINT runner_operation_receipts_result_shape;

ALTER TABLE runner_operation_receipts
    ADD CONSTRAINT runner_operation_receipts_outcome CHECK (
        outcome = ANY (ARRAY[
            'pending', 'claimed', 'claim_expired', 'claim_superseded', 'no_work',
            'attempt_not_found', 'not_queued', 'not_routable',
            'not_runnable', 'slot_out_of_range', 'slot_occupied',
            'scan_superseded', 'authority_rejected'
        ])
    ),
    ADD CONSTRAINT runner_operation_receipts_result_shape CHECK (
        (outcome = 'pending'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NULL
            AND completed_at_ms IS NULL)
        OR (outcome = 'no_work'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL)
        OR (outcome = 'claimed'
            AND claimed_fencing_token IS NOT NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL)
        OR (outcome = ANY (ARRAY['claim_expired', 'claim_superseded'])
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL)
        OR (outcome = 'not_queued'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NOT NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL)
        OR (outcome = 'slot_occupied'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NOT NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL)
        OR (outcome = ANY (ARRAY[
                'attempt_not_found', 'not_routable', 'not_runnable',
                'slot_out_of_range'
            ])
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL)
        OR (outcome = ANY (ARRAY['scan_superseded', 'authority_rejected'])
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NULL
            AND completed_at_ms IS NOT NULL)
    );

COMMENT ON CONSTRAINT runner_operation_receipts_result_shape
    ON runner_operation_receipts IS
    'An admitted lease selection is either replayably live or durably terminal; an undeliverable claim cannot remain replayable as claimed.';
