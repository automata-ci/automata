# Workflow reruns

Automata supports authenticated, durable reruns of completed logical workflow
runs. A rerun creates a new physical run and preserves the original public run
number and public run ID while incrementing the attempt number.

Log in to the target server, then invoke the supported CLI command with the
canonical `OWNER/REPOSITORY` name and completed source-run UUID:

```console
automata auth --server-url https://ci.example.test login
automata rerun --server-url https://ci.example.test \
  automata-ci/automata \
  20000000-0000-4000-8000-000000000002 \
  --selection entire-workflow
```

The other selections are explicit:

```console
automata rerun --server-url https://ci.example.test \
  automata-ci/automata \
  20000000-0000-4000-8000-000000000002 \
  --selection failed-jobs-and-dependents
automata rerun --server-url https://ci.example.test \
  automata-ci/automata \
  20000000-0000-4000-8000-000000000002 \
  --selection job-and-dependents \
  --job-id 30000000-0000-4000-8000-000000000003
```

The CLI loads its bearer only from the same OS credential manager used by
`automata auth` (Secret Service on Linux or Keychain on macOS); it never accepts
or writes a plaintext credential. The command uses this CLI-authenticated
endpoint:

```text
POST /api/v1/repositories/{owner}/{repository}/runs/{source_run_id}/reruns
```

It accepts an `application/json` document no larger than 8 KiB. Content
encoding, query parameters, duplicate JSON fields, non-canonical UUIDs, and
browser sessions are rejected. The caller supplies an operation UUID and one
of these selections:

- `entire_workflow`
- `failed_jobs_and_dependents`
- `job_and_dependents`, with an exact logical job UUID

The operation UUID is the idempotency boundary. An exact replay returns the
existing attempt; reusing it for a different request returns a conflict. By
default the CLI generates one operation UUID, keeps it fixed across its bounded
transport retries, and includes it in every successful table or JSON result. If
the final outcome is indeterminate, the error prints the safe recovery option:

```console
automata rerun --server-url https://ci.example.test \
  automata-ci/automata \
  20000000-0000-4000-8000-000000000002 \
  --selection entire-workflow \
  --operation-id 40000000-0000-4000-8000-000000000004
```

Reuse `--operation-id` only with the exact same repository, source run, and
selection. `--output json` returns `operation_id`, `source_run_id`, the new
physical `run_id`, stable `public_run_id` and `run_number`, `run_attempt`, and
the `replay` flag.
Automation that must persist the identity before any network I/O should create
and record a UUID first, then pass it with `--operation-id`.

Admission resolves the case-insensitive GitHub owner/name coordinate and
reauthorizes the human actor for `runs:rerun` inside the same database
transaction. A missing repository and a repository the caller cannot rerun
produce the same closed response, so the route does not expose repository
existence. The source must have an exact terminal logical result and one terminal
GitHub Check subject. Retention is measured from the attempt-one root using
database time and is currently 30 days. A public run group is limited to 51
total attempts, including attempt one.

Selected jobs receive fresh logical identities. Unselected jobs retain sealed
copies of their exact terminal result and public outputs, so dependency
readiness and final aggregation operate over one effective result view. Failed
job selection includes `failure` and `timed_out`; a cancelled job is not
implicitly classified as failed.

Each physical rerun owns a new GitHub Check subject. The same transaction
creates its projection outbox, records the immutable source manifest, selects
a currently active matching `checks_write` authority, links the subject to the
new physical run, and seals a rerun-specific run-subject digest. Provider I/O
remains outside the transaction and uses the normal fenced Check projection
worker. Finalization updates only the Check linked to that physical run.

Current constraints are deliberate: the source graph must have one root
invocation, every source logical job must use the supported steps execution
kind, and all selected or carried result evidence must be complete. Partial
selection is unavailable when any source job has multiple matrix instances;
the entire workflow can still be rerun. Sources using workflow-level
concurrency currently fail closed because rerun admission does not yet retain
an immutable pre-transition witness proving queue replacement or cancellation
semantics. Sources without the complete current base runtime context also fail
closed; rerun admission does not synthesize a new context or change the source
activation semantics. Requests
outside those boundaries fail closed as conflicts instead of constructing a
best-effort graph.

The PostgreSQL integration tests cover complete reruns, partial and nested
reruns, exact replay, carry-forward, Check projection claims, terminal Check
updates, and evidence immutability. Those live tests require the repository's
configured PostgreSQL test environment.
