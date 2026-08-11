# Getting started

This guide builds both Automata commands from a reviewed source checkout,
starts the local web preview, and describes the currently tested
Linux and Windows runner boundaries.

> [!IMPORTANT]
> No public release has been published. Install from a reviewed source checkout
> and do not guess a version from a planned package or image name.

## Prerequisites

Install [Git](https://git-scm.com/), [rustup](https://rustup.rs/), and a native
C/C++ build toolchain. `rust-toolchain.toml` selects the Rust version and
components used by the repository.

On Windows, use rustup's 64-bit MSVC host and install the Visual Studio Build
Tools **Desktop development with C++** workload. Run Cargo commands from
PowerShell; the same checkout builds native `automata.exe` and
`automata-runner.exe` binaries.

## Run the local preview

```console
git clone https://github.com/automata-ci/automata.git
cd automata
cargo run --locked --bin automata -- preview
```

Open <http://127.0.0.1:8080>. The root redirects to `/repositories`, where the
preview shows an empty repository directory.

Check the server from another terminal:

```console
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

`/healthz` returns process and build information as JSON. `/readyz` returns
`ready` because preview mode has no external dependencies. Stop the process
with `Ctrl-C`.

Preview mode serves the web interface and health endpoints. It does not connect
to PostgreSQL or object storage, accept webhooks, schedule jobs, listen for
runners, or expose the Results API. `automata server` never falls back to this
mode when a production dependency is missing.

## View the hosted demo

<https://automata-ci.github.io/automata/> hosts a static copy of the interface
with sample repositories and runs. It is useful for exploring the screens
without compiling the project. It cannot execute workflows, authenticate
users, or connect to a repository.

## Install both commands

From the reviewed checkout:

```console
cargo install --path crates/automata-ci --locked
cargo install --path crates/automata-ci-runner --locked
```

Cargo installs the commands in `~/.cargo/bin` by default. The first build
downloads and compiles Rust dependencies, then embeds the
checked-in server-side renderer and browser assets, so it may take a few
minutes.

### Windows source-build and native-runner boundary

The experimental native Windows provider executes trusted shell-step workflows
through `automata-runner run`. It uses a fresh workspace and scratch directory
per job plus a Windows Job Object for whole-process-tree cancellation and hard
process, memory, and CPU limits. It advertises process isolation, host network,
host filesystem, and shell steps; it is not a container or virtual-machine
security boundary. A Job Object does not reduce Windows token privileges: each
child retains the dedicated service account's token. Restricted-token launch
is not implemented. The example therefore selects the explicit `host`
privilege policy; this declares unchanged host identity rather than asserting
an unprivileged sandbox identity.

The checked-in
[`runner.windows.example.json`](../crates/automata-ci-runner/config/runner.windows.example.json)
selects the native provider and advertises PowerShell and `cmd.exe` shell steps;
an absolute standalone `python.exe` may also be configured and is probed before
the runner registers.
It deliberately supports only workflow `run:` steps: every `uses:` action,
including JavaScript, composite, local, repository, and container actions,
fails closed. Install the standalone PowerShell 7 MSI or ZIP distribution at
the configured
`C:\Program Files\PowerShell\7\pwsh.exe` path. Microsoft Store/MSIX-packaged
shells and `WindowsApps` execution aliases are rejected because their package
job cannot participate in the runner's single whole-job Job Object.
The current native workspace mapping is also single-slot, so Windows
configuration rejects `max_parallel_jobs` values other than `1`.

Adapt that file only for an already provisioned control plane and object store,
then run:

```powershell
automata-runner run --config C:\path\to\runner.windows.json
```

Use this path only for trusted workflows under a dedicated, non-administrative
runner service account. Administrators must pre-provision restrictive ACLs on
the journal, encrypted spool, native-provider, home, temporary, and tool-cache
roots and their trusted ancestors. The Windows adapter rejects reparse-point
traversal but its current safe, stable-Rust path cannot attest DACL ownership or
hard-link counts. Because jobs inherit the same account and host-filesystem
access, those ACLs protect against other host users, not against the trusted job
itself. Keep the journal free of secret bytes; spool content is authenticated
ciphertext, and workflows must not access runner state paths.

The JSON configuration itself and public TLS roots or certificate chains may be
read from bounded, regular, non-reparse files. Owner-only file policy cannot yet
be proven with the safe Windows adapter, so private keys, spool keys, and object
store credentials must use the example's environment sources. Supply those
variables through the service supervisor's private environment, not an
interactive shell history.

The following runner boundaries fail closed on Windows:

- owner-only file-backed credential and secret sources;
- `automata-runner doctor --active`, which is specifically the Linux rootless
  Podman isolation probe;
- job containers, service containers, and administrator job profiles; and
- every `uses:` action, including JavaScript, composite, local, repository,
  and container actions. Only `run:` steps are supported.

Linux with rootless Podman remains the container-isolated execution-host path.
The Windows path is a pre-1.0 trusted native runner and is not production-ready.
A successful source build or passive doctor report alone is not execution
evidence; the Windows CI contract also runs a real shell-step job through the
native provider. On Linux, a normal dynamically linked Cargo build is still not
a valid `scratch` probe payload for a production runner session.

## Verify the installation

On Linux or macOS:

```console
command -v automata
command -v automata-runner
automata --version
automata-runner --version
```

On Windows PowerShell:

```powershell
Get-Command automata
Get-Command automata-runner
automata --version
automata-runner --version
```

If the commands resolve from different installation directories, remove the
older copies before continuing. Mixing binaries from different source
checkouts can create an accidental version mismatch.

Installing the command does not provision an execution host or prove that it
can execute a job. Linux execution uses rootless Podman; Windows offers the
trusted native provider described above. Inspect a host without starting a
runner:

```console
automata-runner doctor --server http://127.0.0.1:8080 --json
```

The report separates host capability problems from server reachability. Add
`--active` only on a Linux host where it is safe for the diagnostic to create
and remove temporary rootless Podman resources. This ambient doctor check is
useful preparation, but the Linux `automata-runner run` path performs its own
mandatory probe with the configured Podman binary and clean provider
environment before it opens a control-plane session. On Windows, `--active`
returns an error instead of attempting Linux isolation; `run` requires the
explicit native-provider configuration and provisioning described above.

## Start the durable composition

The preview is deliberately small. To use PostgreSQL, object storage,
scheduling, provider ingress, and runner sessions, continue with
[Control-plane setup](deployment.md). Configure an execution host with the
[runner bootstrap guide](../crates/automata-ci-runner/config/README.md).

Read [Compatibility](compatibility.md) before evaluating a workflow. Successful
parsing does not mean that every action or workflow feature is supported.

## Future release channels

The release pipeline is prepared for checksum-verified x86-64 Linux archives,
the crates.io packages `automata-ci` and `automata-ci-runner`, and the GHCR
images `ghcr.io/automata-ci/automata` and
`ghcr.io/automata-ci/automata-runner`.

Use one of those channels only after its registry and
[GitHub Releases](https://github.com/automata-ci/automata/releases) show the
same exact version. The current documentation of a name or publication process
does not make the artifact available.

## Update or remove a source installation

Review the new source revision, then update both commands together:

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

### A command is not found after installation

Add Cargo's binary directory to your shell startup file:

```console
export PATH="$HOME/.cargo/bin:$PATH"
```

Open a new terminal and repeat the four verification commands.

### The Rust toolchain will not install

Update rustup and inspect the toolchain selected for the checkout:

```console
rustup self update
rustup show
```

### Port 8080 is in use

Choose another loopback port and pass the same URL to CLI commands:

```console
automata preview --listen 127.0.0.1:8180
automata admin --server-url http://127.0.0.1:8180 status
```

### Runner diagnostics report missing Podman capabilities

On Linux, use the
[Arch Linux host guide](platforms/arch-linux.md) and rerun the active probe only
after the documented kernel, cgroup, and rootless-networking prerequisites are
in place. The active probe is intentionally unavailable for the native Windows
provider; use the Windows configuration and CI-tested native job path described
above instead.
