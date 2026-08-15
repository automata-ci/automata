# Matrix differential fixture v1

These workflow files are exact candidate inputs for both GitHub Actions and
Automata. The static, expression-axis, and whole-expression forms must produce
the ordered rows in `expected.json`. The include-only source intentionally
contains two identical rows so a comparator must retain both positions rather
than deduplicate by matrix value or digest. The empty-axis source is a negative
fixture and must never publish a partial job set.

The Rust suite compiles the exact bytes through the GitHub frontend, evaluates
them with the production GitHub expression adapter, and compares contexts,
ordering, identities, and digests. That is hermetic component evidence, not a
live GitHub differential observation. `expected.json` therefore keeps
`evidenceClass` set to `candidate` and `liveGithubObservation` set to `null`.
A live adapter must replace neither field in place: it should retain an
immutable GitHub run URL, commit, event/input payload, runner image, timestamps,
and captured observations as a separately reviewed evidence artifact.

Matrix expansion is performed by GitHub's service and its implementation is
not published in `actions/runner`. The semantic baseline for these candidate
expectations is the GitHub Actions documentation reviewed on 2026-08-15:

- <https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations>
- <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstrategymatrix>

The expression evaluator remains pinned separately to `actions/runner`
v2.336.0 at commit `98aabcd429c4e8402406c56ce2d26387fed3b9ce`.
