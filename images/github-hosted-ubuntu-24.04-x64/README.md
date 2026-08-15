# Ubuntu 24.04 x64 compatibility profile

This directory defines the locked Ubuntu 24.04 environment used by the current
integration runner work. It is intended to back the GitHub `ubuntu-24.04`
label, but the control plane does not yet compose a hosted-label profile
catalog. Publishing the image alone does not make that label schedulable.

The Arch Linux runner host stays outside the job. Each admitted job receives a
fresh rootless Podman sandbox using this Ubuntu userspace.

The profile intentionally gives the job UID 0 only inside its rootless user
namespace. It does not use `--privileged`, host sockets, host credentials, or
host mounts other than the one job-owned workspace. The root filesystem is a
writable, disposable container layer because unchanged hosted-runner workflows
use `sudo`, install packages, and start services. For hostile workloads, the
same profile must eventually run behind the stronger Firecracker/Kata adapter;
shared-kernel containers remain a distinct isolation tier.

`profile-manifest.json` is canonical checked-in launch provenance. Its SHA-256
is the environment attestation carried by scheduling and `JobIR`; the OCI image
digest is independently pinned in `profile-lock.json` after a reviewed build.
Manifest schema v2 also records a closed software inventory: exact `dpkg`
versions, absolute executable paths, checksums for standalone archives, and
tools deliberately absent from the profile. The verifier queries every pinned
package inside the exact image, requires every recorded executable to be a
regular executable file, and runs independent version probes for Rust, Cargo,
and Node. A stale package, missing path, mutable image reference, or malformed
inventory rejects the candidate.

Runner startup provides a separate product-admission layer. For every
configured Linux profile, the runner creates and inspects a fresh sandbox from
the digest-qualified image, attaches only after provider evidence matches, and
executes the configured Bash, `sh`, optional Python/PowerShell, GNU
install/tar/SHA, and Node-major probes before advertising inventory. Probe
profiles cannot use host networking, the host filesystem, or the host identity.
An administrator-inside-sandbox profile is admitted only when the provider
advertises both administrator confinement and a user namespace.

The checked-in OCI digest remains a development identity, not a promoted
PLAT-01 image. Its registry manifest predates the current single-squashed-layer
contract and therefore fails the current image verifier before software probes.
The inventory describes that exact immutable identity, but does not manufacture
a signature, accepted publisher provenance, or reproducible rebuild evidence.
Those gates require a new candidate from the accepted Automata issuer.

The image carries Node.js 24.19.0 and the exact renderer tools used by CI:
`wasm-rquickjs-cli` 0.4.1, `cargo-cyclonedx` 0.5.9, and `cargo-deny` 0.20.2.
Node 24.19.0 is the reviewed patch-level delta from the actions/runner v2.336.0
reference runtime recorded in `docs/compatibility.md`.
The pinned `clang-18` package supplies a coherent compiler resource directory,
builtin headers, and the shared Clang C API used by `bindgen` when the unchanged
frontend workflow reproduces the WASI renderer. The image build and opt-in
sandbox contract resolve an exported libclang symbol and the Clang resource
headers without a workflow-specific environment override.

Renderer reproduction also uses the official WASI SDK 24.0 x86_64 Linux
archive from the upstream `wasi-sdk-24` release. The build downloads it over
HTTPS with TLS 1.2 or newer, verifies SHA-256
`c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5`
before extraction, and installs it at the fixed `/opt/wasi-sdk-24.0` root. The
build then compiles a WASI object through that SDK's Clang and sysroot and
archives it through that SDK's `llvm-ar`. The canonical profile manifest
records the archive identity, checksum, installation root, and exact
`WASI_SDK=/opt/wasi-sdk-24.0` toolchain input. The variable is deliberately not
an ambient image environment variable: callers that require the SDK must opt
into the attested root explicitly.

The image contains only a pinned static Docker CLI, not a daemon. When the
runner explicitly enables the typed Docker-compatible capability, the CLI is
connected to an attempt-unique Unix socket mounted at
`/run/automata-engine/docker.sock`. The runner filters that API and backs it
with a fresh per-job Podman store; the full user Podman socket is never mounted.
Child containers share only their owning job's network namespace and are
placed below the outer job cgroup. Host binds, devices, added capabilities,
privileged mode, host namespaces, and native Libpod endpoints are rejected.
The first capability version deliberately uses the bounded legacy image-build
API and does not advertise BuildKit.

## Build locally

Build the profile with the repository-owned wrapper; it keeps build scratch
beneath `target/`, verifies every downloaded standalone archive, and prints the
local image identity:

```console
images/github-hosted-ubuntu-24.04-x64/build-profile.sh
```

The local storage digest is not suitable for registry pinning because a push
may recompress layers and publish a different registry manifest. The build
wrapper never pushes, logs in to a registry, or changes a live runner.

## Publish a reviewed profile

Automated profile publication is disabled. The checked-in workflow fails before
checkout because GitHub's hosted attestation identity cannot authenticate an
Automata job running on a self-hosted runner. It must never be represented as a
GitHub-hosted build.

The safe local preparation path remains:

```console
images/github-hosted-ubuntu-24.04-x64/build-profile.sh
images/github-hosted-ubuntu-24.04-x64/verify-profile-image.sh \
  ghcr.io/automata-ci/automata-ubuntu-24.04-x64:profile-build
```

This produces and verifies only a local image. Its storage digest is not a
registry identity. A separately authorized operator may transfer an already
reviewed image with a least-privilege registry credential, capture the returned
registry digest, pull the exact `@sha256` identity, and rerun the verifier. That
manual transfer does not create trusted provenance or authorize `profile-v1`
or `latest`. Updating `profile-manifest.json`, `profile-lock.json`, runner
examples, or stable tags still requires independent review binding the exact
candidate source commit and remote digest.

The workflow may be enabled only after an accepted Automata issuer binds the
publisher commit, `.ci/workflows/profile-image.yml`, an authenticated Automata
dispatch, the main ref, candidate commit, and the profile-contract,
Containerfile, candidate-source, and image digests. GitHub Actions manual
dispatch is not publication authority. The control plane also does not yet
compose a profile catalog, so publishing an image would not by itself enable
hosted-label scheduling.
