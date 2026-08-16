# Getting started

This guide builds both Automata commands from a reviewed source checkout,
starts the local web preview, and describes the Linux runner boundary and the
documented experimental Windows boundary.

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

### Windows Hyper-V-container source-build boundary

The checked-in
[`runner.windows.example.json`](../crates/automata-ci-runner/config/runner.windows.example.json)
selects `windows_hyperv` and schema version 5. It defines an absolute local
container CLI path and SHA-256, a digest-qualified Windows Server Core image,
an in-image guest executable, an in-container workspace, disabled networking,
a writable container root, `ContainerUser`, and CPU, memory, and process
limits.

The example's image and runtime digests are placeholders. It will not work
until a laboratory Windows Server 2025 host has the Hyper-V and Containers
roles, the selected Windows container engine, an exact preloaded compatible
image containing the guest executable and configured shells, and real reviewed
digests. The provider never pulls at job startup. It creates with explicit
Hyper-V isolation and verifies the effective isolation, network, user, image,
entrypoint, resource, ownership, and no-mount state before executing a step.

The current Windows executor admits only workflow `run:` steps. JavaScript,
composite, local, repository, and container `uses:` actions, job and service
containers, egress, devices, administrator profiles, and reboot/interactive
semantics fail closed or remain unaccepted. PowerShell, Windows PowerShell,
`cmd.exe`, optional Python, and every configured path must exist inside the
immutable image; host shell paths are not mounted into the job.

Adapt the file only for an offline component laboratory with an already
provisioned control plane, object store, engine, and qualified image, then run:

```powershell
automata-runner run --config C:\path\to\runner.windows.json
```

Run the runner under a dedicated non-administrative service identity.
Pre-provision restrictive ACLs on journal, encrypted spool,
`state.windows_hyperv`, configuration, runtime, update, and evidence roots and
their trusted ancestors. Keep the journal free of secret bytes; spool content
is authenticated ciphertext, and workflows must never access runner state or
the container-engine endpoint.

The JSON configuration and public TLS roots or certificate chains may be read
from bounded regular non-reparse files. Private keys, spool keys, and object
store credentials must use the example's environment sources until the
Windows credential-custody contract is implemented. Supply them through the
service supervisor's private environment, not an interactive shell history.

The following runner boundaries fail closed on Windows:

- owner-only file-backed credential and secret sources;
- `automata-runner doctor --active`, which is specifically the Linux rootless
  Podman isolation probe;
- job containers, service containers, networked and administrator profiles;
  and
- every `uses:` action, including JavaScript, composite, local, repository,
  and container actions. Only `run:` steps are supported.

The Windows path remains pre-1.0 component code and is not production-ready. A
successful source build, injected-runtime test, passive doctor report, or local
container create is not isolation evidence. Hosted Windows CI is disabled
because Automata does not operate an accepted Windows fleet. Do not deploy this
path for repository workloads until the
[Windows isolation plan](platforms/windows.md) completes authenticated
`EVT-01` -> `AUTH-02` -> `WIN-ISO-01` routing, the restricted management
and recovery gates, and dedicated-host IT-09/GATE-02 acceptance. On Linux, a
normal dynamically linked Cargo build is still not a valid `scratch` probe
payload for a production runner session.

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
can execute a job. Linux execution uses rootless Podman; the Windows
Hyper-V-container provider remains an offline component foundation. Inspect a
host without starting a runner:

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
explicit `windows_hyperv` configuration, engine, image, and laboratory
provisioning described above.

## Configure the complete server

The preview is deliberately small. To use PostgreSQL, object storage,
scheduling, provider ingress, and runner sessions, provide the required
external services and follow the [`automata` configuration
reference](../crates/automata-ci/README.md). Configure an execution host with
the [runner bootstrap guide](../crates/automata-ci-runner/config/README.md).

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

On Linux, review the host requirements in the [runner bootstrap
guide](../crates/automata-ci-runner/config/README.md) and rerun the active probe
only after its kernel, cgroup, and rootless-networking prerequisites are in
place. That Podman diagnostic does not apply to Windows. Windows startup
instead performs create, inspect, guest-probe, shell-probe, and destroy
admission through the Hyper-V-container provider. Do not deploy it until the
physical Windows end-to-end gate is accepted.
