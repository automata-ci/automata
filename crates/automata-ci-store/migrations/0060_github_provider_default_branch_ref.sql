-- Revision the configured canonical default-branch ref into provider manifests.
-- Existing main-branch rows retain their historical v3/v4 digest bytes.

ALTER TABLE github_provider_manifest_revisions
    DROP CONSTRAINT github_provider_manifest_revisions_digest_canonical,
    DROP CONSTRAINT github_provider_manifest_revisions_selector_exact;

CREATE FUNCTION automata_github_provider_git_ref_canonical(value TEXT)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
WITH candidate AS (
    SELECT substr(value, 12) AS branch
)
SELECT octet_length(value) BETWEEN 12 AND 1024
   AND left(value, 11) = 'refs/heads/'
   AND branch <> ''
   AND branch <> '@'
   AND left(branch, 1) NOT IN ('-', '/', '.')
   AND right(branch, 1) NOT IN ('/', '.')
   AND strpos(branch, '//') = 0
   AND strpos(branch, '..') = 0
   AND strpos(branch, '@{') = 0
   AND branch !~ '[[:cntrl:][:space:]]'
   AND strpos(branch, '~') = 0
   AND strpos(branch, '^') = 0
   AND strpos(branch, ':') = 0
   AND strpos(branch, '?') = 0
   AND strpos(branch, '*') = 0
   AND strpos(branch, '[') = 0
   AND strpos(branch, chr(92)) = 0
   AND NOT EXISTS (
       SELECT 1
       FROM unnest(string_to_array(branch, '/')) AS component(value)
       WHERE component.value = ''
          OR left(component.value, 1) = '.'
          OR right(component.value, 5) = '.lock'
   )
FROM candidate
$automata$;

ALTER TABLE github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_selector_exact CHECK (
        event_name = 'push'
        AND automata_github_provider_git_ref_canonical(git_ref)
        AND check_subject_key = workflow_path
        AND (
            workflow_selection_kind = 'exact'
            AND workflow_path ~ '^\.github/workflows/[^/]+\.ya?ml$'
            OR workflow_selection_kind = 'all_direct'
            AND workflow_path = '.github/workflows'
        )
        AND workflow_path !~ '[[:cntrl:]\\]'
    );

DO $automata$
DECLARE
    current_definition TEXT;
    patched_definition TEXT;
    old_domain CONSTANT TEXT :=
        '        CASE ($1).workflow_selection_kind' || chr(10) ||
        '            WHEN ''exact'' THEN ''automata.store.github-provider-manifest.v3''' || chr(10) ||
        '            WHEN ''all_direct'' THEN ''automata.store.github-provider-manifest.v4.all-direct''' || chr(10) ||
        '            ELSE ''invalid''' || chr(10) ||
        '        END,';
    new_domain CONSTANT TEXT :=
        '        CASE' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''exact''' || chr(10) ||
        '             AND ($1).git_ref = ''refs/heads/main''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v3''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''all_direct''' || chr(10) ||
        '             AND ($1).git_ref = ''refs/heads/main''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v4.all-direct''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''exact''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v5.git-ref''' || chr(10) ||
        '            WHEN ($1).workflow_selection_kind = ''all_direct''' || chr(10) ||
        '                THEN ''automata.store.github-provider-manifest.v5.all-direct.git-ref''' || chr(10) ||
        '            ELSE ''invalid''' || chr(10) ||
        '        END,';
BEGIN
    SELECT pg_get_functiondef(
        'automata_github_provider_manifest_digest(github_provider_manifest_revisions)'::REGPROCEDURE
    ) INTO current_definition;
    IF strpos(current_definition, old_domain) = 0 THEN
        RAISE EXCEPTION 'unexpected GitHub provider manifest digest definition'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_provider_manifest_git_ref_digest_upgrade_exact';
    END IF;
    patched_definition := replace(current_definition, old_domain, new_domain);
    IF patched_definition = current_definition
        OR strpos(patched_definition, old_domain) > 0
    THEN
        RAISE EXCEPTION 'GitHub provider manifest digest upgrade was incomplete'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_provider_manifest_git_ref_digest_upgrade_exact';
    END IF;
    EXECUTE patched_definition;
END;
$automata$;

ALTER TABLE github_provider_manifest_revisions
    ADD CONSTRAINT github_provider_manifest_revisions_digest_canonical CHECK (
        manifest_digest = automata_github_provider_manifest_digest(
            github_provider_manifest_revisions
        )
    );
