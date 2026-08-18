# Getting started

This guide installs Automata from source, verifies both commands, checks a
workflow without running it, and points to the complete deployment path.

To inspect execution evidence first, open the
[Checks for main commit `280cd4f9`](https://github.com/automata-ci/automata/commit/280cd4f9e685ac022c65a920ba24f4f019b0fd25/checks).
The aggregate and job Checks point to the
[current Automata CI dashboard run](https://ci.automata-ci.com/automata-ci/automata/actions/runs/99ab4504-ef90-8aa1-ad24-34d1811b1c00);
dashboard access follows the repository's current publication and sign-in
policy.

## Prerequisites

Install:

- [Git](https://git-scm.com/);
- [rustup](https://rustup.rs/); and
- a native C/C++ build toolchain.

The repository's `rust-toolchain.toml` selects the Rust version and components.
On Windows, use rustup's 64-bit MSVC host and install the Visual Studio Build
Tools **Desktop development with C++** workload.

This guide uses a source installation. Build from a revision you have reviewed;
package and image names found in release automation are not installation
channels until the matching version exists publicly.

## Install the commands

```console
git clone https://github.com/automata-ci/automata.git
cd automata
cargo install --path crates/automata-ci --locked
cargo install --path crates/automata-ci-runner --locked
```

Cargo installs executables in `~/.cargo/bin` by default. Verify that both
commands came from the same checkout:

```console
command -v automata
command -v automata-runner
automata --version
automata-runner --version
```

On Windows PowerShell, replace `command -v` with `Get-Command`.

## Check the host

`automata local doctor` checks the supported host tuple, Docker Engine, and
Compose plugin without creating containers or local state:

```console
automata local doctor
automata local doctor --json
```

Use the JSON form in scripts. A successful report means the local-installation
prerequisites passed; it does not install services or execute a workflow.

To inspect a runner host and optional server endpoint:

```console
automata-runner doctor --server http://127.0.0.1:8080 --json
```

Plain HTTP is accepted only for a literal loopback address. Add `--active` only
on a Linux host where the diagnostic may safely create and remove temporary
rootless Podman resources. The normal `automata-runner run` startup repeats its
mandatory checks against the configured provider.

## Check a workflow

`automata local check` validates one exact Git snapshot without network access,
a GitHub token, server admission, or job execution. The workflow must be a
direct `.github/workflows/*.yml` or `.yaml` file with a `workflow_dispatch`
trigger.

From the root of your Git worktree:

```console
automata local check .github/workflows/ci.yml
```

For a workflow with manual inputs:

```console
automata local check .github/workflows/release.yml \
  --input environment=staging \
  --input publish=false
```

The command validates the selected workflow and reachable local reusable
workflows, reports required credentials without exposing their values, and
returns a nonzero status for unsupported or invalid behavior. It does not run
steps or prove that actions, credentials, and provider services will succeed at
runtime. See the [local command boundary](../crates/automata-ci-local/README.md)
for snapshot rules and limits.

Repositories connected to the Automata server keep executable workflows under
`.ci/workflows`. The `.github/workflows` path above is the deliberate local
inspection boundary; Automata does not use it as a server-side fallback.

## Deploy Automata

The complete path requires:

- PostgreSQL for mutable state and coordination;
- S3-compatible storage for immutable payloads;
- TLS and signing keys for runner control and Results;
- a configured GitHub App; and
- at least one enrolled execution host.

The source tree does not yet provide a standalone GitHub-provider onboarding
command or turnkey deployment bundle. The running composition receives GitHub
App and repository desired state through its private, mutually-authenticated
shard-management API. Do not populate its PostgreSQL tables by hand. Until a
self-hosted provisioning client is available, the supported first-user paths in
this repository are source installation, host inspection, and local
workflow checking; complete deployment requires the external provisioning
authority described in the control-plane reference.

Follow the [`automata` deployment and configuration
reference](../crates/automata-ci/README.md), then the [runner bootstrap
guide](../crates/automata-ci-runner/config/README.md). Read
[Compatibility](compatibility.md) before moving an existing workflow; parsing
alone does not prove that an action or runtime feature is supported.

After the server starts, verify process health and dependency readiness:

```console
curl --fail https://ci.example.com/healthz
curl --fail https://ci.example.com/readyz
```

The runner bootstrap guide continues with one-time enrollment, capability
inspection, provider admission, and `automata-runner run`.

## Update or remove a source installation

Review the new revision, then update both commands from the same checkout:

```console
cargo install --path crates/automata-ci --locked --force
cargo install --path crates/automata-ci-runner --locked --force
```

Remove them with:

```console
cargo uninstall automata-ci
cargo uninstall automata-ci-runner
```

## Troubleshooting

### The command is not found

Add Cargo's binary directory to your shell startup file:

```console
export PATH="$HOME/.cargo/bin:$PATH"
```

Open a new terminal and repeat the version checks.

### The Rust toolchain will not install

```console
rustup self update
rustup show
```

`rustup show` should list the toolchain selected by `rust-toolchain.toml` while
you are inside the repository.

### Runner diagnostics report missing capabilities

Review the provider prerequisites and admission checks in the [runner bootstrap
guide](../crates/automata-ci-runner/config/README.md). Do not bypass a failed
probe: the runner withholds unsupported capabilities and refuses unsafe host or
sandbox state.
