-- G1 connection fencing, immutable execution metadata, and retry receipts.
-- Existing pre-G1 active leases cannot be authenticated to a connection
-- epoch. They are deliberately failed closed as lost during this upgrade.

ALTER TABLE runners
    ADD COLUMN session_epoch BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT runners_session_epoch_nonnegative CHECK (session_epoch >= 0),
    ADD CONSTRAINT runners_slots_u16 CHECK (slots <= 65535);

-- A durable compatibility epoch prevents a pre-G1 writer from silently
-- admitting a label-only schema-v1 job after hosted environment attestation
-- becomes mandatory. Current writers must explicitly name epoch 2; there is
-- intentionally no default that an old INSERT can inherit.
CREATE TABLE automata_cluster_compatibility (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    minimum_admission_epoch INTEGER NOT NULL,
    job_ir_schema INTEGER NOT NULL,
    runner_requirements_schema INTEGER NOT NULL,
    CONSTRAINT automata_cluster_compatibility_singleton CHECK (singleton),
    CONSTRAINT automata_cluster_compatibility_g1 CHECK (
        minimum_admission_epoch = 2
        AND job_ir_schema = 3
        AND runner_requirements_schema = 2
    )
);

INSERT INTO automata_cluster_compatibility (
    singleton, minimum_admission_epoch, job_ir_schema, runner_requirements_schema
) VALUES (TRUE, 2, 3, 2);

ALTER TABLE runner_sessions
    ADD COLUMN runner_generation BIGINT,
    ADD COLUMN session_epoch BIGINT,
    ADD COLUMN last_command_sequence BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN acknowledged_command_sequence BIGINT NOT NULL DEFAULT 0;

WITH numbered AS (
    SELECT session.id,
           runner.generation AS runner_generation,
           row_number() OVER (
               PARTITION BY session.runner_id
               ORDER BY session.connected_at_ms, session.id
           ) AS session_epoch
    FROM runner_sessions AS session
    JOIN runners AS runner ON runner.id = session.runner_id
)
UPDATE runner_sessions AS session
SET runner_generation = numbered.runner_generation,
    session_epoch = numbered.session_epoch
FROM numbered
WHERE session.id = numbered.id;

UPDATE runners AS runner
SET session_epoch = epochs.maximum_epoch
FROM (
    SELECT runner_id, max(session_epoch) AS maximum_epoch
    FROM runner_sessions
    GROUP BY runner_id
) AS epochs
WHERE runner.id = epochs.runner_id;

UPDATE runner_sessions
SET heartbeat_at_ms = greatest(heartbeat_at_ms, connected_at_ms),
    disconnected_at_ms = CASE
        WHEN disconnected_at_ms IS NULL THEN NULL
        ELSE greatest(disconnected_at_ms, heartbeat_at_ms, connected_at_ms)
    END;

-- A pre-G1 session selected a schema that this binary no longer executes and
-- did not carry the new admission epoch. It may remain historical but cannot
-- be resumed by a v3 runner.
UPDATE runner_sessions
SET disconnected_at_ms = heartbeat_at_ms
WHERE disconnected_at_ms IS NULL;

UPDATE runners
SET status = 'offline'
WHERE status = 'online';

ALTER TABLE runner_sessions
    ALTER COLUMN runner_generation SET NOT NULL,
    ALTER COLUMN session_epoch SET NOT NULL,
    ADD CONSTRAINT runner_sessions_protocol_u16 CHECK (protocol_version <= 65535),
    ADD CONSTRAINT runner_sessions_job_ir_u16 CHECK (job_ir_schema <= 65535),
    ADD CONSTRAINT runner_sessions_live_job_ir_v3 CHECK (
        disconnected_at_ms IS NOT NULL OR job_ir_schema = 3
    ),
    ADD CONSTRAINT runner_sessions_generation_positive CHECK (runner_generation > 0),
    ADD CONSTRAINT runner_sessions_epoch_positive CHECK (session_epoch > 0),
    ADD CONSTRAINT runner_sessions_heartbeat_monotonic CHECK (
        heartbeat_at_ms >= connected_at_ms
    ),
    ADD CONSTRAINT runner_sessions_disconnect_monotonic CHECK (
        disconnected_at_ms IS NULL OR disconnected_at_ms >= heartbeat_at_ms
    ),
    ADD CONSTRAINT runner_sessions_command_sequence_nonnegative CHECK (
        last_command_sequence >= 0
    ),
    ADD CONSTRAINT runner_sessions_command_cursor_valid CHECK (
        acknowledged_command_sequence BETWEEN 0 AND last_command_sequence
    ),
    ADD CONSTRAINT runner_sessions_runner_epoch_unique UNIQUE (runner_id, session_epoch),
    ADD CONSTRAINT runner_sessions_fence_unique UNIQUE (
        runner_id, id, session_epoch, runner_generation
    );

DROP INDEX runner_sessions_live_by_runner;
CREATE UNIQUE INDEX runner_sessions_one_live_per_runner
    ON runner_sessions (runner_id)
    WHERE disconnected_at_ms IS NULL;

CREATE TABLE runner_queue_cursors (
    runner_id UUID NOT NULL REFERENCES runners(id) ON DELETE CASCADE,
    runner_slot INTEGER NOT NULL,
    runner_generation BIGINT NOT NULL,
    routing_fingerprint BYTEA NOT NULL,
    cursor_version BIGINT NOT NULL,
    after_queued_at_ms BIGINT,
    after_attempt_id UUID,
    cycle_upper_queued_at_ms BIGINT,
    cycle_upper_attempt_id UUID,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT runner_queue_cursors_primary_key PRIMARY KEY (runner_id, runner_slot),
    CONSTRAINT runner_queue_cursors_slot_range CHECK (
        runner_slot BETWEEN 1 AND 65535
    ),
    CONSTRAINT runner_queue_cursors_generation_positive CHECK (
        runner_generation > 0
    ),
    CONSTRAINT runner_queue_cursors_sha256 CHECK (
        octet_length(routing_fingerprint) = 32
    ),
    CONSTRAINT runner_queue_cursors_version_positive CHECK (
        cursor_version > 0
    ),
    CONSTRAINT runner_queue_cursors_after_complete CHECK (
        (after_queued_at_ms IS NULL) = (after_attempt_id IS NULL)
    ),
    CONSTRAINT runner_queue_cursors_upper_complete CHECK (
        (cycle_upper_queued_at_ms IS NULL) = (cycle_upper_attempt_id IS NULL)
    ),
    CONSTRAINT runner_queue_cursors_after_within_cycle CHECK (
        after_queued_at_ms IS NULL
        OR cycle_upper_queued_at_ms IS NULL
        OR (after_queued_at_ms, after_attempt_id)
            <= (cycle_upper_queued_at_ms, cycle_upper_attempt_id)
    )
);

ALTER TABLE jobs
    ADD COLUMN admission_epoch INTEGER,
    ADD COLUMN job_ir_schema INTEGER,
    ADD COLUMN job_ir_size_bytes BIGINT;

-- Legacy rows have no trustworthy object size or executable schema. Preserve
-- them as historical records without fabricating metadata, and make all later
-- writers explicitly opt into the v2 admission contract.
UPDATE jobs SET admission_epoch = 1;

ALTER TABLE jobs
    ALTER COLUMN admission_epoch SET NOT NULL,
    DROP COLUMN runner_group,
    DROP COLUMN labels,
    ADD CONSTRAINT jobs_admission_epoch_range CHECK (
        admission_epoch BETWEEN 1 AND 2
    ),
    ADD CONSTRAINT jobs_ir_metadata_complete CHECK (
        (job_ir_schema IS NULL) = (job_ir_size_bytes IS NULL)
    ),
    ADD CONSTRAINT jobs_current_admission_metadata CHECK (
        (
            admission_epoch = 1
            AND job_ir_schema IS NULL
            AND job_ir_size_bytes IS NULL
        ) OR (
            admission_epoch = 2
            AND job_ir_schema = 3
            AND job_ir_size_bytes BETWEEN 1 AND 16777216
            AND requirements @> '{"schema_version": 2}'::jsonb
        )
    ),
    ADD CONSTRAINT jobs_run_id_unique UNIQUE (run_id, id);

CREATE FUNCTION automata_reject_job_plan_update()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'immutable Automata job plans cannot be updated'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'jobs_plan_immutable';
END;
$automata$;

CREATE TRIGGER jobs_plan_immutable
BEFORE UPDATE ON jobs
FOR EACH ROW
EXECUTE FUNCTION automata_reject_job_plan_update();

CREATE TABLE job_dependencies (
    run_id UUID NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    job_id UUID NOT NULL,
    prerequisite_job_id UUID NOT NULL,
    CONSTRAINT job_dependencies_primary_key PRIMARY KEY (
        run_id, job_id, prerequisite_job_id
    ),
    CONSTRAINT job_dependencies_no_self_edge CHECK (job_id <> prerequisite_job_id),
    CONSTRAINT job_dependencies_job_same_run
        FOREIGN KEY (run_id, job_id)
        REFERENCES jobs(run_id, id) ON DELETE CASCADE,
    CONSTRAINT job_dependencies_prerequisite_same_run
        FOREIGN KEY (run_id, prerequisite_job_id)
        REFERENCES jobs(run_id, id) ON DELETE CASCADE
);

CREATE INDEX job_dependencies_prerequisites
    ON job_dependencies (run_id, prerequisite_job_id, job_id);

ALTER TABLE workflow_runs
    ADD COLUMN concurrency_group_key TEXT,
    ADD CONSTRAINT workflow_runs_concurrency_key_shape CHECK (
        concurrency_group_key IS NULL OR (
            octet_length(concurrency_group_key) BETWEEN 1 AND 255
            AND concurrency_group_key !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT workflow_runs_concurrency_group_exists
        FOREIGN KEY (repository_id, concurrency_group_key)
        REFERENCES concurrency_groups(repository_id, normalized_key)
        ON DELETE RESTRICT;

CREATE INDEX workflow_runs_runnable_status
    ON workflow_runs (status, created_at_ms, id)
    WHERE status IN ('queued', 'in_progress');

UPDATE job_attempts
SET lifecycle = 'lost',
    lease_id = NULL,
    runner_id = NULL,
    lease_issued_at_ms = NULL,
    lease_expires_at_ms = NULL,
    lease_failures = lease_failures + 1
WHERE lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing');

UPDATE job_attempts AS attempt
SET lifecycle = 'skipped'
FROM jobs AS job
WHERE attempt.job_id = job.id
  AND job.admission_epoch = 1
  AND attempt.lifecycle = 'queued';

ALTER TABLE job_attempts
    ADD COLUMN runner_session_id UUID,
    ADD COLUMN runner_session_epoch BIGINT,
    ADD COLUMN runner_generation BIGINT,
    ADD COLUMN runner_slot INTEGER;

ALTER TABLE job_attempts
    DROP CONSTRAINT job_attempts_lease_fields_consistent,
    ADD CONSTRAINT job_attempts_lease_fields_consistent CHECK (
        (
            lease_id IS NULL
            AND runner_id IS NULL
            AND lease_issued_at_ms IS NULL
            AND lease_expires_at_ms IS NULL
            AND runner_session_id IS NULL
            AND runner_session_epoch IS NULL
            AND runner_generation IS NULL
            AND runner_slot IS NULL
        )
        OR
        (
            lease_id IS NOT NULL
            AND runner_id IS NOT NULL
            AND lease_issued_at_ms IS NOT NULL
            AND lease_expires_at_ms IS NOT NULL
            AND runner_session_id IS NOT NULL
            AND runner_session_epoch IS NOT NULL
            AND runner_generation IS NOT NULL
            AND runner_slot IS NOT NULL
        )
    ),
    ADD CONSTRAINT job_attempts_session_epoch_positive CHECK (
        runner_session_epoch IS NULL OR runner_session_epoch > 0
    ),
    ADD CONSTRAINT job_attempts_runner_generation_positive CHECK (
        runner_generation IS NULL OR runner_generation > 0
    ),
    ADD CONSTRAINT job_attempts_runner_slot_range CHECK (
        runner_slot IS NULL OR runner_slot BETWEEN 1 AND 65535
    ),
    ADD CONSTRAINT job_attempts_session_fence
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        )
        REFERENCES runner_sessions (
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT;

CREATE UNIQUE INDEX job_attempts_live_runner_slot_unique
    ON job_attempts (runner_id, runner_slot)
    WHERE lease_id IS NOT NULL;

CREATE TABLE runner_command_outbox (
    runner_session_id UUID NOT NULL,
    command_sequence BIGINT NOT NULL,
    operation_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    command_kind TEXT NOT NULL,
    command_schema INTEGER NOT NULL,
    command_digest BYTEA NOT NULL,
    command_payload BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT runner_command_outbox_primary_key PRIMARY KEY (
        runner_session_id, command_sequence
    ),
    CONSTRAINT runner_command_outbox_operation_unique UNIQUE (
        runner_session_id, operation_id
    ),
    CONSTRAINT runner_command_outbox_session_fence
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        )
        REFERENCES runner_sessions (
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT runner_command_outbox_sequence_positive CHECK (command_sequence > 0),
    CONSTRAINT runner_command_outbox_kind_shape CHECK (
        octet_length(command_kind) BETWEEN 1 AND 128
        AND command_kind ~ '^[a-z0-9][a-z0-9._/-]*$'
    ),
    CONSTRAINT runner_command_outbox_schema_range CHECK (
        command_schema BETWEEN 1 AND 65535
    ),
    CONSTRAINT runner_command_outbox_sha256 CHECK (octet_length(command_digest) = 32),
    CONSTRAINT runner_command_outbox_payload_size CHECK (
        octet_length(command_payload) BETWEEN 1 AND 16777216
    )
);

CREATE INDEX runner_command_outbox_replay
    ON runner_command_outbox (runner_session_id, command_sequence);

CREATE TABLE runner_rpc_receipts (
    runner_session_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    operation_kind TEXT NOT NULL,
    request_digest BYTEA NOT NULL,
    response_schema INTEGER NOT NULL,
    response_digest BYTEA NOT NULL,
    response_payload BYTEA NOT NULL,
    committed_at_ms BIGINT NOT NULL,
    CONSTRAINT runner_rpc_receipts_primary_key PRIMARY KEY (
        runner_session_id, operation_id
    ),
    CONSTRAINT runner_rpc_receipts_session_fence
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        )
        REFERENCES runner_sessions (
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT runner_rpc_receipts_kind_shape CHECK (
        octet_length(operation_kind) BETWEEN 1 AND 128
        AND operation_kind ~ '^[a-z0-9][a-z0-9._/-]*$'
    ),
    CONSTRAINT runner_rpc_receipts_request_sha256 CHECK (
        octet_length(request_digest) = 32
    ),
    CONSTRAINT runner_rpc_receipts_response_schema CHECK (
        response_schema BETWEEN 1 AND 65535
    ),
    CONSTRAINT runner_rpc_receipts_response_sha256 CHECK (
        octet_length(response_digest) = 32
    ),
    CONSTRAINT runner_rpc_receipts_response_size CHECK (
        octet_length(response_payload) BETWEEN 1 AND 16777216
    )
);

CREATE TABLE attempt_cancellation_intents (
    attempt_id UUID PRIMARY KEY REFERENCES job_attempts(id) ON DELETE CASCADE,
    operation_id UUID NOT NULL UNIQUE,
    requested_by TEXT NOT NULL,
    reason TEXT,
    requested_at_ms BIGINT NOT NULL,
    acknowledged_at_ms BIGINT,
    delivery_session_id UUID,
    delivery_command_sequence BIGINT,
    CONSTRAINT attempt_cancellation_actor_shape CHECK (
        octet_length(requested_by) BETWEEN 1 AND 255
        AND requested_by !~ '[[:cntrl:]]'
    ),
    CONSTRAINT attempt_cancellation_reason_shape CHECK (
        reason IS NULL OR (
            octet_length(reason) BETWEEN 1 AND 1024
            AND reason !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT attempt_cancellation_ack_monotonic CHECK (
        acknowledged_at_ms IS NULL OR acknowledged_at_ms >= requested_at_ms
    ),
    CONSTRAINT attempt_cancellation_delivery_complete CHECK (
        (delivery_session_id IS NULL AND delivery_command_sequence IS NULL)
        OR
        (delivery_session_id IS NOT NULL AND delivery_command_sequence IS NOT NULL)
    ),
    CONSTRAINT attempt_cancellation_delivery_command
        FOREIGN KEY (delivery_session_id, delivery_command_sequence)
        REFERENCES runner_command_outbox(runner_session_id, command_sequence)
        ON DELETE RESTRICT
);

CREATE TABLE runner_operation_receipts (
    runner_session_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    operation_kind TEXT NOT NULL,
    request_digest BYTEA NOT NULL,
    selection_kind TEXT NOT NULL,
    requested_attempt_id UUID,
    requested_lease_id UUID,
    runner_slot INTEGER NOT NULL,
    scan_cursor_version BIGINT NOT NULL,
    committed_cursor_version BIGINT,
    observed_at_ms BIGINT NOT NULL,
    lease_expires_at_ms BIGINT,
    outcome TEXT NOT NULL,
    claimed_fencing_token BIGINT,
    rejection_lifecycle TEXT,
    occupied_attempt_id UUID,
    claimed_job_id UUID,
    claimed_run_id UUID,
    claimed_job_ir_schema INTEGER,
    claimed_job_ir_size_bytes BIGINT,
    claimed_job_ir_digest BYTEA,
    claimed_job_ir_object_key TEXT,
    completed_at_ms BIGINT,
    CONSTRAINT runner_operation_receipts_primary_key PRIMARY KEY (
        runner_session_id, operation_id
    ),
    CONSTRAINT runner_operation_receipts_session_fence
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        )
        REFERENCES runner_sessions (
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT runner_operation_receipts_kind_shape CHECK (
        octet_length(operation_kind) BETWEEN 1 AND 128
        AND operation_kind !~ '[[:cntrl:]]'
    ),
    CONSTRAINT runner_operation_receipts_sha256 CHECK (
        octet_length(request_digest) = 32
    ),
    CONSTRAINT runner_operation_receipts_selection_kind CHECK (
        selection_kind IN ('claim', 'no_work')
    ),
    CONSTRAINT runner_operation_receipts_slot_range CHECK (
        runner_slot BETWEEN 1 AND 65535
    ),
    CONSTRAINT runner_operation_receipts_lease_interval CHECK (
        lease_expires_at_ms IS NULL OR lease_expires_at_ms > observed_at_ms
    ),
    CONSTRAINT runner_operation_receipts_cursor_versions CHECK (
        scan_cursor_version >= 0
        AND (
            committed_cursor_version IS NULL
            OR committed_cursor_version = scan_cursor_version + 1
        )
    ),
    CONSTRAINT runner_operation_receipts_outcome CHECK (
        outcome IN (
            'pending', 'claimed', 'no_work', 'attempt_not_found', 'not_queued',
            'not_routable', 'not_runnable', 'slot_out_of_range', 'slot_occupied',
            'scan_superseded'
        )
    ),
    CONSTRAINT runner_operation_receipts_fence_positive CHECK (
        claimed_fencing_token IS NULL OR claimed_fencing_token > 0
    ),
    CONSTRAINT runner_operation_receipts_rejection_lifecycle CHECK (
        rejection_lifecycle IS NULL OR rejection_lifecycle IN (
            'queued', 'leased', 'preparing', 'running', 'cancelling', 'finalizing',
            'succeeded', 'failed', 'cancelled', 'timed_out', 'skipped', 'lost'
        )
    ),
    CONSTRAINT runner_operation_receipts_selection_shape CHECK (
        (
            selection_kind = 'no_work'
            AND requested_attempt_id IS NULL
            AND requested_lease_id IS NULL
            AND lease_expires_at_ms IS NULL
        ) OR (
            selection_kind = 'claim'
            AND requested_attempt_id IS NOT NULL
            AND requested_lease_id IS NOT NULL
            AND lease_expires_at_ms IS NOT NULL
        )
    ),
    CONSTRAINT runner_operation_receipts_job_ir_shape CHECK (
        (
            outcome = 'claimed'
            AND claimed_job_id IS NOT NULL
            AND claimed_run_id IS NOT NULL
            AND claimed_job_ir_schema = 3
            AND claimed_job_ir_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(claimed_job_ir_digest) = 32
            AND octet_length(claimed_job_ir_object_key) BETWEEN 1 AND 1024
        ) OR (
            outcome <> 'claimed'
            AND claimed_job_id IS NULL
            AND claimed_run_id IS NULL
            AND claimed_job_ir_schema IS NULL
            AND claimed_job_ir_size_bytes IS NULL
            AND claimed_job_ir_digest IS NULL
            AND claimed_job_ir_object_key IS NULL
        )
    ),
    CONSTRAINT runner_operation_receipts_result_shape CHECK (
        (
            outcome = 'pending'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NULL
            AND completed_at_ms IS NULL
        ) OR (
            outcome = 'no_work'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome = 'claimed'
            AND claimed_fencing_token IS NOT NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome = 'not_queued'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NOT NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome = 'slot_occupied'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NOT NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome IN (
                'attempt_not_found', 'not_routable', 'not_runnable', 'slot_out_of_range'
            )
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome = 'scan_superseded'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NULL
            AND completed_at_ms IS NOT NULL
        )
    )
);

CREATE INDEX runner_operation_receipts_attempt
    ON runner_operation_receipts (requested_attempt_id, completed_at_ms);

CREATE TABLE attempt_terminal_results (
    attempt_id UUID PRIMARY KEY REFERENCES job_attempts(id) ON DELETE CASCADE,
    runner_session_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    runner_slot INTEGER NOT NULL,
    lease_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    result_schema INTEGER NOT NULL,
    result_size_bytes BIGINT NOT NULL,
    result_digest BYTEA NOT NULL,
    result_object_key TEXT NOT NULL,
    conclusion TEXT NOT NULL,
    completed_at_ms BIGINT NOT NULL,
    committed_at_ms BIGINT NOT NULL,
    CONSTRAINT attempt_terminal_results_operation_unique UNIQUE (
        runner_session_id, operation_id
    ),
    CONSTRAINT attempt_terminal_results_session_fence
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        )
        REFERENCES runner_sessions (
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT attempt_terminal_results_slot_range CHECK (
        runner_slot BETWEEN 1 AND 65535
    ),
    CONSTRAINT attempt_terminal_results_fence_positive CHECK (fencing_token > 0),
    CONSTRAINT attempt_terminal_results_schema_range CHECK (
        result_schema BETWEEN 1 AND 65535
    ),
    CONSTRAINT attempt_terminal_results_size_range CHECK (
        result_size_bytes BETWEEN 1 AND 16777216
    ),
    CONSTRAINT attempt_terminal_results_sha256 CHECK (
        octet_length(result_digest) = 32
    ),
    CONSTRAINT attempt_terminal_results_object_key_shape CHECK (
        octet_length(result_object_key) BETWEEN 1 AND 1024
        AND result_object_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT attempt_terminal_results_conclusion CHECK (
        conclusion IN ('success', 'failure', 'cancelled', 'timed_out', 'skipped')
    ),
    CONSTRAINT attempt_terminal_results_time_monotonic CHECK (
        committed_at_ms >= completed_at_ms
    )
);

CREATE TABLE attempt_log_streams (
    id UUID PRIMARY KEY,
    attempt_id UUID NOT NULL REFERENCES job_attempts(id) ON DELETE CASCADE,
    runner_session_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    runner_slot INTEGER NOT NULL,
    lease_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    log_schema INTEGER NOT NULL,
    opened_at_ms BIGINT NOT NULL,
    closed_at_ms BIGINT,
    CONSTRAINT attempt_log_streams_operation_unique UNIQUE (
        runner_session_id, operation_id
    ),
    CONSTRAINT attempt_log_streams_attempt_id_unique UNIQUE (attempt_id, id),
    CONSTRAINT attempt_log_streams_session_fence
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        )
        REFERENCES runner_sessions (
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT attempt_log_streams_slot_range CHECK (runner_slot BETWEEN 1 AND 65535),
    CONSTRAINT attempt_log_streams_fence_positive CHECK (fencing_token > 0),
    CONSTRAINT attempt_log_streams_schema_range CHECK (log_schema BETWEEN 1 AND 65535),
    CONSTRAINT attempt_log_streams_close_monotonic CHECK (
        closed_at_ms IS NULL OR closed_at_ms >= opened_at_ms
    )
);

CREATE TABLE attempt_log_segments (
    stream_id UUID NOT NULL REFERENCES attempt_log_streams(id) ON DELETE CASCADE,
    operation_id UUID NOT NULL,
    first_sequence BIGINT NOT NULL,
    last_sequence BIGINT NOT NULL,
    object_key TEXT NOT NULL,
    object_digest BYTEA NOT NULL,
    encoded_size_bytes BIGINT NOT NULL,
    uncompressed_size_bytes BIGINT NOT NULL,
    stored_at_ms BIGINT NOT NULL,
    end_of_stream BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT attempt_log_segments_primary_key PRIMARY KEY (stream_id, first_sequence),
    CONSTRAINT attempt_log_segments_operation_unique UNIQUE (stream_id, operation_id),
    CONSTRAINT attempt_log_segments_last_unique UNIQUE (stream_id, last_sequence),
    CONSTRAINT attempt_log_segments_sequence_range CHECK (
        first_sequence >= 0 AND last_sequence >= first_sequence
    ),
    CONSTRAINT attempt_log_segments_object_key_shape CHECK (
        octet_length(object_key) BETWEEN 1 AND 1024
        AND object_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT attempt_log_segments_sha256 CHECK (octet_length(object_digest) = 32),
    CONSTRAINT attempt_log_segments_encoded_size CHECK (
        encoded_size_bytes BETWEEN 1 AND 67108864
    ),
    CONSTRAINT attempt_log_segments_uncompressed_size CHECK (
        uncompressed_size_bytes BETWEEN 1 AND 268435456
    )
);

CREATE UNIQUE INDEX attempt_log_segments_one_terminal
    ON attempt_log_segments (stream_id)
    WHERE end_of_stream;
