# Windows local evaluation design

Status: **Planned; [issue #66](https://github.com/automata-ci/automata/issues/66)
requires design review before implementation.**

This page defines a small, single-machine path for evaluating Automata on
Windows. It does not change the production support status of `automata server`.
The separate [durable Windows control-plane proposal](windows-control-plane-design-proposal.md)
and [release roadmap](windows-release-roadmap.md) retain the production service,
custody, recovery, installer, and release requirements investigated in issue
#16 and PR #30.

## Evaluation outcome

A new contributor should be able to clone a reviewed checkout and use one
command to:

1. start loopback-only development dependencies;
2. start one local control-plane process;
3. start one native Windows runner;
4. submit one workflow from the current repository;
5. inspect the run in the local web interface; and
6. stop the processes and explicitly retain or delete their state.

The intended command shape is:

```powershell
automata demo --repo . --workflow .ci/workflows/test.yml
```

The command and flags are design placeholders until the implementation is
reachable and tested. Documentation must not present them as available before
then.

## Position in the product

Automata should expose three distinct paths:

| Command | Purpose | Executes workflows | Durability claim |
| --- | --- | --- | --- |
| `automata preview` | Inspect health endpoints and the web interface | No | None |
| `automata demo` | Evaluate one trusted repository on one Windows machine | Yes | Disposable local evaluation state |
| `automata server` | Operate the complete control plane | Yes | Platform-specific production contract |

`automata demo` must be a separate product boundary. It must not be implemented
as `automata server --insecure`, and production startup must not fall back to it
when an adapter or dependency is unavailable.

## Initial workflow surface

The first Windows evaluation milestone supports only the capabilities already
proved by the native provider:

- trusted `run:` steps;
- PowerShell Core, Windows PowerShell, and `cmd.exe` where configured;
- one runner and one job at a time; and
- a repository selected from the local filesystem.

Every `uses:` action, job or service container, administrator profile, remote
runner, and hostile workload remains unsupported and fails closed. Product
copy should say “run a trusted workflow or shell steps locally,” not “run
GitHub Actions locally,” until action execution has its own evidence.

## Enforced evaluation boundary

The demo composition must enforce these limits in code:

- every HTTP and runner-control listener binds a literal loopback address;
- exactly one local repository and one local native runner are admitted;
- concurrency is fixed at one job;
- no inbound GitHub webhook or public provider listener starts;
- no Windows service, scheduled task, startup registration, or remote runner is
  created;
- credentials are generated for this composition, bounded in lifetime, and
  never accepted as production credentials;
- state lives below a dedicated `%LOCALAPPDATA%\Automata\Demo` root or an
  explicit temporary root;
- the web interface and terminal identify the process as `EVALUATION MODE`;
- shutdown has a bounded child-process teardown; and
- state deletion is explicit and verifies that the selected root is a demo
  root before removal.

These restrictions are part of the command contract, not recommendations that
a user can accidentally omit.

## Local dependencies

The durable control plane depends on PostgreSQL and S3-compatible object
storage. The evaluation path should reuse those production adapters rather than
create in-memory, SQLite, or ordinary-filesystem substitutes with different
transaction and object semantics.

The first implementation may orchestrate the existing pinned PostgreSQL and
RustFS development composition through an explicitly detected container tool.
On Windows this is likely Docker Desktop or another reviewed Compose-compatible
runtime. The command must:

- detect the tool before changing state;
- show which pinned images and ports it will use;
- bind dependency ports to loopback;
- use generated per-demo credentials instead of checked-in development
  defaults;
- wait for dependency-specific health checks;
- distinguish infrastructure startup from Automata startup failures; and
- leave unrelated containers and volumes untouched during cleanup.

Bundling PostgreSQL or object-storage binaries is a separate distribution and
licensing decision. It is not required for the first evaluation milestone.

## Lifecycle sketch

The coordinator owns one explicit state machine:

```text
validate inputs
  -> acquire demo-root lock
  -> prepare generated identity and dependency configuration
  -> start and verify PostgreSQL and object storage
  -> initialize the control-plane schema and bucket
  -> start and verify the loopback control plane
  -> start and verify one native runner
  -> admit the selected local workflow
  -> print the run and UI locations
  -> wait, stop, or retain by explicit policy
```

Failure at any step tears down only children created by that invocation. A
small manifest in the demo root records process/container identities and
supports bounded recovery after interruption. Cleanup must treat identity
mismatches as errors rather than deleting by a reused process ID or container
name.

## Security model

The workflow is trusted as the interactive Windows user. Job Object containment
provides process-tree accounting and termination; it does not reduce the user
token, isolate the network, or create a hostile-workload sandbox. The command
must display this boundary before first execution and provide a non-interactive
acknowledgement flag for automation.

Generated demo credentials protect components from accidental cross-talk; they
do not turn the single-user composition into a multi-tenant service. Secrets
must not appear in command lines, shell history, process titles, logs, or the UI.
Environment-backed values, if required for child startup, exist only in the
coordinator-created child environment and are not accepted by the production
Windows service path.

## Acceptance evidence

The feature becomes Experimental only after a clean Windows host proves:

1. the documented command starts from a reviewed source checkout;
2. all listeners and dependency ports are loopback-only;
3. one fixture containing supported `run:` steps completes through the real
   compiler, scheduler, protocol, native provider, results, and UI paths;
4. unsupported `uses:` and container fixtures fail with exact errors;
5. Ctrl-C and injected startup failures stop invocation-owned children;
6. `--keep` preserves the documented state and a later invocation recovers it;
7. reset removes only a valid demo root and its invocation-owned resources;
8. logs and diagnostics contain no generated credentials; and
9. Linux production composition tests remain unchanged.

## Work packages

1. Review this boundary and choose the supported Windows container orchestrator.
2. Extract a coordinator interface with deterministic lifecycle tests.
3. Add loopback, single-runner, and single-job configuration constructors that
   cannot represent production exposure.
4. Add dependency discovery, startup, health, and ownership manifests.
5. Add local repository admission without opening a webhook listener.
6. Connect the existing native Windows runner and enforce its capability set.
7. Add interruption, cleanup, unsupported-workflow, and secret-redaction tests.
8. Publish a short getting-started tutorial only after the complete command is
   covered by native acceptance evidence.
