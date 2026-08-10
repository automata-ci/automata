# Getting started

This guide builds both Automata commands from a reviewed source checkout,
starts the dependency-free web preview, and verifies the control plane and
runner diagnostics.

> [!IMPORTANT]
> No public release has been published yet. The GitHub Pages preview, prebuilt
> archive, crates.io packages, and product GHCR images are not currently
> available. Use only the reviewed source installation below; do not guess a
> tag or infer availability from a planned package or image name.

## Install Automata

The source checkout is the only current installation path. It installs the two
commands `automata` and `automata-runner` into Cargo's normal binary directory.

### Install from a reviewed source checkout

Install [Git](https://git-scm.com/),
[rustup](https://rustup.rs/), and a native C/C++ build toolchain first. The
repository pins Rust 1.97.1 and its required components in
`rust-toolchain.toml`.

On Windows, use rustup's 64-bit MSVC host and install the
[Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/)
**Desktop development with C++** workload. Run the source-build commands below
from PowerShell. The same checkout and Cargo commands build native
`automata.exe` and `automata-runner.exe` binaries.

```console
git clone https://github.com/automata-ci/automata.git
cd automata
cargo install --path crates/automata-ci --locked
cargo install --path crates/automata-ci-runner --locked
```

The first build downloads and compiles Rust dependencies, then embeds the
checked-in server-side renderer and browser assets, so it may take a few
minutes.

### Windows source-build boundary

A native Windows source build provides a deliberately limited preview and
diagnostic surface. It supports:

- `automata preview` on a loopback address;
- `automata admin status` against that preview; and
- passive `automata-runner doctor` diagnostics, including an optional preview
  health check.

It does not make Windows an execution host or a production control-plane
platform. The following boundaries fail closed on Windows:

- `automata auth` and `automata secret` operator commands;
- file-backed credential and secret sources;
- static runner registration files and the full `automata server` deployment
  composition;
- `automata-runner doctor --active`, which requires rootless Podman network
  isolation; and
- `automata-runner run` and native job execution.

Linux with rootless Podman remains the only supported job-execution host. A
successful Windows build or passive doctor report is evidence only for the
preview and diagnostics listed above.

A compiled runner is useful for diagnostics, but it is not proof that the host
can execute jobs. The initial execution-host path is Linux with rootless Podman,
and a normal dynamically linked Cargo build is not a valid `scratch` probe
payload for a production runner session.

### Future release channels

Only after an exact version appears under
[GitHub Releases](https://github.com/automata-ci/automata/releases) should users
expect its tag-bound checksum-verifying x86-64 Linux installer and static
archive. The planned matching registry names are the crates.io packages
`automata-ci` and `automata-ci-runner` and the GHCR repositories
`ghcr.io/automata-ci/automata` and `ghcr.io/automata-ci/automata-runner`.

Treat each channel independently as unavailable until it visibly contains the
same exact version. Never substitute the moving `main` installer for a release,
guess a version, or assume that a documented registry name has been published.

## Verify the installation

On Linux:

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

## Start the preview

```console
automata preview --listen 127.0.0.1:8080
```

Open <http://127.0.0.1:8080>. The browser follows the canonical redirect to
`/repositories` and should show an empty repository directory. That confirms
the Rust HTTP server, embedded React renderer, static assets, and WASI runtime
all started successfully.

From another terminal, verify health and CLI connectivity:

```console
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
automata admin status
```

On Windows PowerShell, use the native HTTP command and the same explicit
loopback origin:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/healthz
Invoke-RestMethod http://127.0.0.1:8080/readyz
automata --server-url http://127.0.0.1:8080 admin status
```

`/healthz` returns process identity and build information as JSON. `/readyz`
returns `ready` in preview mode. `automata admin status` reads both endpoints
and reports process health separately from dependency readiness.

Inspect the local runner host without starting a runner:

```console
automata-runner doctor --server http://127.0.0.1:8080 --json
```

The report separates host capability problems from server reachability. Add
`--active` only on a Linux host where it is safe for the diagnostic to create
and remove temporary rootless Podman resources. This ambient doctor check is
useful preparation, but `automata-runner run` performs its own mandatory probe
with the configured Podman binary and clean provider environment before it
opens a control-plane session. On Windows, `--active` and `run` return an error
instead of attempting Linux isolation or job execution.

Stop the preview with `Ctrl-C`.

## Future preview container

After a product image is published for an exact GitHub Release, its
control-plane image will provide the same preview without a host Rust toolchain.
No such product image is public today, so use the source preview above. Future
release images target Linux x86-64; the planned runner image distributes and
diagnoses the runner binary but does not provision a host or replace the
rootless Podman setup in the [runner-host guide](platforms/arch-linux.md).

## What preview mode does

Preview mode serves:

- `/healthz` and `/readyz`;
- the canonical `/` redirect and server-rendered `/repositories` directory; and
- embedded, content-hashed browser assets.

It does not connect to PostgreSQL or object storage, admit workflows, schedule
jobs, listen for runners, or expose the Results API. This is deliberate: a
missing production dependency can never make `automata server` fall back to a
weaker mode.

## Update or remove Automata

Select and review the source commit you want to run, then reinstall both
packages from that checkout. Update them together so the two commands never
silently drift across revisions:

```console
cargo install --path crates/automata-ci --locked --force
cargo install --path crates/automata-ci-runner --locked --force
```

To remove the source-installed Cargo packages:

```console
cargo uninstall automata-ci
cargo uninstall automata-ci-runner
```

## Next steps

- Follow [control-plane setup](deployment.md) to start PostgreSQL, RustFS, the
  complete bootstrap server composition, and the optional configured GitHub
  provider ingress.
- Follow [runner bootstrap](../crates/automata-ci-runner/config/README.md) only
  if you are working on the experimental end-to-end Linux path.
- Read the [compatibility contract](compatibility.md) before evaluating a
  workflow. A parsed workflow is not automatically a compatible workflow.
- Use the [development guide](development.md) for tests, frontend work, and
  distribution builds.

## Troubleshooting

### A release or hosted-preview URL returns HTTP 404

That is expected before the first public release and Pages deployment. Use the
source installation and local preview documented above. After publication,
trust only an exact version visibly listed under
[GitHub Releases](https://github.com/automata-ci/automata/releases); a planned
package or image name is not availability evidence.

### The commands are not found after installation

Cargo installs source packages in `~/.cargo/bin` by default. Add that directory
to `PATH` in your shell startup file:

```console
export PATH="$HOME/.cargo/bin:$PATH"
```

Open a new terminal and rerun the four installation verification commands.

### A future installer rejects this platform

There is no public installer to troubleshoot today. If an exact GitHub Release
later publishes one, use it only on a platform named by that release; otherwise
build from the reviewed source checkout. Execution hosts still need the Linux
and rootless Podman capabilities documented by the runner-host guide.

### A future checksum or executable verification fails

There is no public archive to verify today. After an exact release is
published, do not bypass its checksum or executable verification. Retry on a
trusted network; if the same release fails again, report the version and
installer output without uploading local credentials.

### The pinned Rust version will not install

Update rustup itself, then ask it to inspect the repository toolchain:

```console
rustup self update
rustup show
```

`rustup show` should list the toolchain selected by `rust-toolchain.toml`.

### Port 8080 is already in use

Choose another loopback port and pass the same server URL to administration
commands:

```console
automata preview --listen 127.0.0.1:8180
automata --server-url http://127.0.0.1:8180 admin status
```

### The runner doctor reports missing Podman capabilities

That does not affect preview mode. For an execution host, use the
[Arch Linux host guide](platforms/arch-linux.md) and rerun the active probe only
after the documented kernel, cgroup, and rootless-networking prerequisites are
in place.
