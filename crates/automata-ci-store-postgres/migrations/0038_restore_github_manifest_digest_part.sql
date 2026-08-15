-- The frozen event-trust migration made the manifest digest depend on this
-- domain-specific length-prefix primitive but omitted its definition.  Keep
-- the canonical digest implementation singular and make the dependency
-- explicit in the forward-only migration lineage.

CREATE FUNCTION automata_github_provider_manifest_digest_part(bytea) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN pg_catalog.int8send(pg_catalog.octet_length($1)::BIGINT) || $1;

-- Resolve and execute the exact dependency while this migration is applied.
-- This prevents a clean database from accepting another lazily unresolved
-- manifest-digest function body.
DO $$
BEGIN
    PERFORM automata_github_provider_manifest_digest_part(''::BYTEA);
END;
$$;
