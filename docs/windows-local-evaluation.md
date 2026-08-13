# Run a trusted workflow locally on Windows

Status: **Experimental on the feature branch tracked by
[issue #66](https://github.com/automata-ci/automata/issues/66).**

The local demo parses and compiles one workflow, copies its repository into a
disposable workspace, and executes literal `run:` steps with the trusted native
Windows provider. It also serves the existing Automata browser interface on
loopback with the live run status, job, and captured logs. It does not start
PostgreSQL, object storage, a control plane, or a runner service.

The separate [durable Windows control-plane proposal](windows-control-plane-design-proposal.md)
and [release roadmap](windows-release-roadmap.md) retain the production service,
custody, recovery, installer, and release requirements investigated in issue
#16 and PR #30.

## Trust boundary

> [!WARNING]
> Demo processes inherit the current Windows user token. The Job Object bounds
> the process tree and provides whole-tree termination, but it does not isolate
> the filesystem, network, or user identity. Run only workflows you trust and
> do not run the command from an administrator shell.

The demo is deliberately separate from `automata server`. Production startup
never falls back to this path when an adapter or dependency is unavailable.

## Run the demo

Install rustup's 64-bit MSVC host and the Visual Studio Build Tools **Desktop
development with C++** workload. From a reviewed source checkout, create or
select a workflow containing one Windows job and literal shell steps:

```yaml
name: Local smoke
on: workflow_dispatch
jobs:
  smoke:
    runs-on: windows
    steps:
      - name: Build
        shell: powershell
        run: cargo check --workspace
```

Run it from PowerShell:

```powershell
cargo run --locked --bin automata -- demo `
  --repo . `
  --workflow .ci/workflows/test.yml `
  --allow-host-execution
```

The acknowledgement flag is mandatory. The command prints a URL such as:

```text
Visual run page: http://127.0.0.1:8080/local/evaluation/actions/runs/...
```

Open it in a browser. The ordinary Automata run and job-log pages refresh once
per second while showing queued, in-progress, and completed state plus captured
standard output, standard error, and step lifecycle messages. A successful run
ends with `demo workflow completed successfully`.

The visual server remains available after execution so the result can be
inspected. Press `Ctrl-C` to stop it. Use `--no-visual` for automation that must
exit immediately; this does not weaken execution validation. `--listen` may
select another literal-loopback address but rejects non-loopback binds.

The command deletes its temporary workspace after success or failure. It does
not modify the selected repository.

## Implemented limits

The first executable slice accepts:

- Windows only;
- one repository and exactly one workflow job;
- workflows selected by `workflow_dispatch`;
- literal `run:` scripts and literal step names;
- `powershell`, `pwsh`, and `cmd` shells; and
- sequential execution in one copied workspace.

It fails closed for:

- every `uses:` action;
- multiple jobs, dependencies, matrices, conditions, concurrency, services, and
  containers;
- workflow, job, or step environment mappings;
- expressions in scripts, names, or shell selections;
- `continue-on-error`, per-step timeouts, working-directory overrides, resource
  overrides, deployment environments, and reusable workflows;
- repositories larger than 4096 regular files or 64 MiB after excluding
  `.git`, `target`, and `.automata`; and
- symbolic links, junctions, and unsupported filesystem entries.

Workflow input is bounded to 1 MiB, each script to 16384 UTF-16 units, and each
step's aggregate output to 4 MiB. Each step has a 30-minute ceiling. Standalone
PowerShell 7 must be installed at
`C:\Program Files\PowerShell\7\pwsh.exe` when `shell: pwsh` is selected; inbox
Windows PowerShell and `cmd.exe` use their system paths.

## What this proves

The current slice reuses:

```text
workflow YAML
  -> loss-aware GitHub workflow frontend
  -> provider-neutral workflow compiler
  -> validated logical plan
  -> trusted Windows Job Object provider
  -> bounded native process execution
  -> in-memory projection into the existing SSR run and job-log pages
```

It does not claim to prove durable scheduling, runner transport, authentication,
results publication, PostgreSQL transactions, S3 object behavior, service
lifecycle, or reboot recovery.

## Path to a local control-plane composition

The demo is the first rung rather than a second control plane:

1. **Native local execution** — the current disposable single-job path.
2. **Local durable composition** — the real `automata server`, PostgreSQL, S3
   adapter, and one native runner, kept loopback-only for evaluation.
3. **Production Windows control plane** — separate service identities, reviewed
   credential custody, SCM lifecycle, reboot recovery, MSI upgrades, and signed
   artifacts from issue #16.

Workflow syntax, compilation, logical plans, shell behavior, and native provider
execution carry forward. Demo history does not migrate into PostgreSQL.

The local demo must not grow an alternate scheduler, database, runner protocol,
authentication system, or object store. Features requiring those boundaries
belong in the local durable composition.

## Next implementation slices

1. Execute through the full GitHub job executor so command files, environment
   layering, conditions, and supported expressions use the production path.
2. Add a native end-to-end test that invokes the shipped `automata` process and
   verifies the visual routes plus cleanup after success, failure, and interruption.
3. Replace one-second page refreshes with a bounded live-update transport.
4. Add bounded cancellation on Ctrl-C rather than waiting for the current step
   timeout.
5. Add selected multi-step semantics without enabling `uses:` actions.
6. Design the separate loopback durable composition after the native demo is a
   reliable onboarding path.
