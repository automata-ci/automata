# Ubuntu 24.04 x64 compatibility profile

This image is the initial immutable environment behind the GitHub
`ubuntu-24.04` label. The Arch Linux runner host remains outside the job; each
job receives a fresh rootless Podman sandbox using this Ubuntu userspace.

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
The embedded Node
runtime matches the recorded actions/runner v2.336.0 compatibility baseline.
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
