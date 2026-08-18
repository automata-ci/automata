-- Keep per-workflow Checks distinct from the delivery-wide required Check.

CREATE FUNCTION automata_github_workflow_check_name(TEXT, TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE PARALLEL SAFE STRICT
AS $$
SELECT CASE
    WHEN octet_length($1) + 3 + octet_length($2) <= 255
        THEN $1 || ' / ' || $2
    ELSE left($1, 179) || ' / workflow-' ||
         pg_catalog.encode(
             pg_catalog.sha256(pg_catalog.convert_to($2, 'UTF8')),
             'hex'
         )
END
$$;
