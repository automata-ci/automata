-- Provider-delivery admissions carry their authenticated manifest and service
-- authorities directly. They intentionally do not create GitHub subject
-- evidence rows, so the currentness guard must not require that older edge.
DO $migration$
DECLARE
    definition TEXT;
    original_edge CONSTANT TEXT := 'AND admission_receipt.github_subject_evidence_required';
    provider_delivery_edge CONSTANT TEXT :=
        'AND (origin.origin_kind = ''provider_delivery'' OR admission_receipt.github_subject_evidence_required)';
BEGIN
    SELECT pg_get_functiondef(routine.oid)
      INTO definition
      FROM pg_proc AS routine
      JOIN pg_namespace AS namespace
        ON namespace.oid = routine.pronamespace
     WHERE routine.proname = 'automata_github_runtime_authority_base_is_current'
       AND namespace.nspname = 'public'
       AND pg_get_function_identity_arguments(routine.oid) =
           'authority github_runtime_authority_issuances, observed_at bigint';

    IF definition IS NULL OR position(original_edge IN definition) = 0 THEN
        RAISE EXCEPTION
            'runtime-authority currentness guard does not expose its admission evidence edge';
    END IF;

    definition := replace(definition, original_edge, provider_delivery_edge);
    EXECUTE definition;
END;
$migration$;
