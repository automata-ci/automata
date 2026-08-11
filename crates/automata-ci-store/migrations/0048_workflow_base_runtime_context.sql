-- Bind one canonical provider-neutral base runtime context to each new logical
-- workflow admission and copy its immutable descriptor into preparation claims.

LOCK TABLE workflow_runs IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1 FROM workflow_runs WHERE status IN ('queued', 'in_progress')
    ) THEN
        RAISE EXCEPTION 'workflow base context upgrade requires drained active runs'
            USING ERRCODE = '55000';
    END IF;
END;
$automata$;

ALTER TABLE workflow_plan_v2_runs
    ADD COLUMN base_context_digest BYTEA,
    ADD COLUMN base_context_object_key TEXT COLLATE "C",
    ADD COLUMN base_context_size_bytes BIGINT,
    ADD COLUMN base_context_media_type TEXT COLLATE "C",
    ADD COLUMN base_context_schema SMALLINT,
    ADD CONSTRAINT workflow_plan_v2_runs_base_context CHECK (
        (
            base_context_digest IS NULL
            AND base_context_object_key IS NULL
            AND base_context_size_bytes IS NULL
            AND base_context_media_type IS NULL
            AND base_context_schema IS NULL
        ) OR (
            base_context_digest IS NOT NULL
            AND base_context_object_key IS NOT NULL
            AND base_context_size_bytes IS NOT NULL
            AND base_context_media_type IS NOT NULL
            AND base_context_schema IS NOT NULL
            AND octet_length(base_context_digest) = 32
            AND octet_length(base_context_object_key) BETWEEN 1 AND 1024
            AND base_context_object_key !~ '[[:cntrl:]]'
            AND left(base_context_object_key, 1) <> '/'
            AND base_context_object_key !~ '(^|/)\.\.(/|$)'
            AND base_context_size_bytes BETWEEN 1 AND 16777216
            AND base_context_media_type =
                'application/vnd.automata.job-runtime-context.protobuf'
            AND base_context_schema = 2
        )
    );

CREATE FUNCTION automata_reject_logical_run_base_context_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.base_context_digest IS DISTINCT FROM OLD.base_context_digest
        OR NEW.base_context_object_key IS DISTINCT FROM OLD.base_context_object_key
        OR NEW.base_context_size_bytes IS DISTINCT FROM OLD.base_context_size_bytes
        OR NEW.base_context_media_type IS DISTINCT FROM OLD.base_context_media_type
        OR NEW.base_context_schema IS DISTINCT FROM OLD.base_context_schema
    THEN
        RAISE EXCEPTION 'logical workflow base context is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_runs_base_context_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_runs_base_context_immutable
BEFORE UPDATE OF base_context_digest, base_context_object_key,
                 base_context_size_bytes, base_context_media_type,
                 base_context_schema
ON workflow_plan_v2_runs
FOR EACH ROW
EXECUTE FUNCTION automata_reject_logical_run_base_context_mutation();

ALTER TABLE workflow_plan_v2_activation_preparation_claims
    ADD COLUMN base_context_digest BYTEA,
    ADD COLUMN base_context_object_key TEXT COLLATE "C",
    ADD COLUMN base_context_size_bytes BIGINT,
    ADD COLUMN base_context_media_type TEXT COLLATE "C",
    ADD COLUMN base_context_schema SMALLINT,
    DROP CONSTRAINT workflow_plan_v2_activation_preparation_claims_authority,
    ADD CONSTRAINT workflow_plan_v2_activation_preparation_claims_authority CHECK (
        automata_is_canonical_logical_activation_workspace(workspace)
        AND (
            (
                base_context_kind = 'root_empty'
                AND base_context_digest IS NULL
                AND base_context_object_key IS NULL
                AND base_context_size_bytes IS NULL
                AND base_context_media_type IS NULL
                AND base_context_schema IS NULL
            ) OR (
                base_context_kind = 'admission_v2'
                AND base_context_digest IS NOT NULL
                AND base_context_object_key IS NOT NULL
                AND base_context_size_bytes IS NOT NULL
                AND base_context_media_type IS NOT NULL
                AND base_context_schema IS NOT NULL
                AND octet_length(base_context_digest) = 32
                AND octet_length(base_context_object_key) BETWEEN 1 AND 1024
                AND base_context_object_key !~ '[[:cntrl:]]'
                AND left(base_context_object_key, 1) <> '/'
                AND base_context_object_key !~ '(^|/)\.\.(/|$)'
                AND base_context_size_bytes BETWEEN 1 AND 16777216
                AND base_context_media_type =
                    'application/vnd.automata.job-runtime-context.protobuf'
                AND base_context_schema = 2
            )
        )
    );

CREATE FUNCTION automata_validate_logical_preparation_base_context()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        WHERE marker.run_id = NEW.run_id
          AND (
              (
                  NEW.base_context_kind = 'root_empty'
                  AND marker.base_context_digest IS NULL
                  AND marker.base_context_object_key IS NULL
                  AND marker.base_context_size_bytes IS NULL
                  AND marker.base_context_media_type IS NULL
                  AND marker.base_context_schema IS NULL
              ) OR (
                  NEW.base_context_kind = 'admission_v2'
                  AND marker.base_context_digest = NEW.base_context_digest
                  AND marker.base_context_object_key = NEW.base_context_object_key
                  AND marker.base_context_size_bytes = NEW.base_context_size_bytes
                  AND marker.base_context_media_type = NEW.base_context_media_type
                  AND marker.base_context_schema = NEW.base_context_schema
                  AND marker.base_context_schema = 2
              )
          )
    ) THEN
        RAISE EXCEPTION 'logical preparation base context disagrees with admission'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_activation_preparation_base_context_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparation_base_context_exact
BEFORE INSERT ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW
EXECUTE FUNCTION automata_validate_logical_preparation_base_context();

CREATE FUNCTION automata_reject_logical_preparation_base_context_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.base_context_digest IS DISTINCT FROM OLD.base_context_digest
        OR NEW.base_context_object_key IS DISTINCT FROM OLD.base_context_object_key
        OR NEW.base_context_size_bytes IS DISTINCT FROM OLD.base_context_size_bytes
        OR NEW.base_context_media_type IS DISTINCT FROM OLD.base_context_media_type
        OR NEW.base_context_schema IS DISTINCT FROM OLD.base_context_schema
    THEN
        RAISE EXCEPTION 'logical preparation base context is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_activation_preparation_base_context_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparation_base_context_immutable
BEFORE UPDATE OF base_context_digest, base_context_object_key,
                 base_context_size_bytes, base_context_media_type,
                 base_context_schema
ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW
EXECUTE FUNCTION automata_reject_logical_preparation_base_context_mutation();
