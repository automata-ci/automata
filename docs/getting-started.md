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

### Windows Hyper-V-container component boundary

Windows has no current deployment configuration or supported
`automata-runner run` path. The Hyper-V provider remains an internal component
fixture until native atomic TLS renewal custody, a promoted immutable image,
authenticated placement evidence, and the dedicated physical-host acceptance
gate land together. Do not reconstruct a configuration from tests or pass
private material through environment variables; no static-certificate or
environment-backed fallback is supported. Follow the
[Windows isolation plan](platforms/windows.md) for the remaining qualification
work.

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
returns an error instead of attempting Linux isolation, and there is no
supported `automata-runner run` path.

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
