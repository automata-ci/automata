# Getting started

This guide builds both Automata commands from source, starts the local web
preview, and checks that the binaries work.

> [!IMPORTANT]
> No public release has been published. Install from a reviewed source checkout
> and do not guess a version from a planned package or image name.

## Prerequisites

Install [Git](https://git-scm.com/), [rustup](https://rustup.rs/), and a native
C/C++ build toolchain. `rust-toolchain.toml` selects the Rust version and
components used by the repository.

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

Cargo installs the commands in `~/.cargo/bin` by default. Verify both names and
versions:

```console
command -v automata
command -v automata-runner
automata --version
automata-runner --version
```

The initial runner path is Linux with rootless Podman. Installing the command
does not prepare the host or prove that it can execute a job. You can inspect a
host without starting a runner:

```console
automata-runner doctor --server http://127.0.0.1:8080 --json
```

Add `--active` only on a Linux host where the diagnostic may create and remove
temporary rootless Podman resources. The runner repeats its mandatory checks
before opening a control-plane session.

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

That does not affect preview mode. For an execution host, follow the
[Arch Linux host guide](platforms/arch-linux.md) and repeat the active probe
after configuring its kernel, cgroup, and rootless-networking prerequisites.
