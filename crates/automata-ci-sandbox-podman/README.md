# automata-ci-sandbox-podman

`automata-ci-sandbox-podman` implements Automata's whole-job sandbox contracts
with local, rootless Podman. Commands use bounded argument lists and an
allowlisted environment; the adapter does not mount a Podman socket, forward
host credentials, or issue global prune operations.

`automata-runner` composes this adapter behind `automata-ci-execution` for the
current Linux execution path.

## Optional closed BuildKit runtime

BuildKit is disabled by default. `PodmanOptions::with_buildkit_runtime` accepts
one immutable, untagged `@sha256:` image reference and is valid only with the
attempt-scoped Docker-compatible API. Provider construction verifies that the
exact digest already exists in the private shared rootless-Podman store, checks
the inspected digest, and runs `buildkitd --version` with pulls and networking
disabled, a read-only root, all capabilities dropped, no-new-privileges, and
finite memory/PID limits. The provider advertises `BuildKit` only after those
checks succeed. Each job imports the verified image into its separate engine
graph through a private temporary OCI archive; the archive and the entire
attempt engine are removed during exact job cleanup.

The Docker proxy implements the current default
`docker/setup-buildx-action` `docker-container` request surface used by
`docker/build-push-action`, including BuildKit's `buildctl dial-stdio` stream
and the generated GitHub Actions provenance file needed alongside CacheService
v2 sessions. The default `moby/buildkit:buildx-stable-1` pull is a synthetic
local alias for the configured digest and never contacts a registry. One
exactly named helper, its state volume, and its bounded exec IDs are scoped to
one attempt. The helper runs in the job network namespace and cgroup beneath a
rootless Podman engine; its sole writable mount is its attempt-local state
volume.

This is deliberately not a general Docker daemon. The proxy accepts only the
reviewed default Buildx daemon command, including its exact
`security.insecure` and `network.host` entitlement arguments; custom daemon
flags fail closed. Custom BuildKit images, driver resource/network options,
host binds, devices, custom security options, arbitrary privileged containers,
extra archive files, and cross-attempt helper objects also fail closed. Unknown
future create fields require an explicit policy review. `DOCKER_BUILDKIT=0`
remains set for the separately supported legacy `docker build` API; Buildx
invokes BuildKit directly and does not use that switch.

The ordinary test suite exercises the complete proxy lifecycle against a
synthetic Unix-socket backend. A deployment still needs opt-in live rootless
acceptance for its exact Podman, Buildx, BuildKit image, kernel, and CacheService
v2 endpoint before enabling the pin in production.

The ignored Buildx acceptance fixture is enabled separately from the existing
rootless-Podman fixture with `AUTOMATA_LIVE_ROOTLESS_BUILDX=1` and reads the
preloaded untagged digest pin from `AUTOMATA_PODMAN_TEST_BUILDKIT_IMAGE`. It
performs a `docker-container` bootstrap, one neutral `FROM scratch` build, and
exact builder/attempt cleanup. It does not claim live CacheService v2 coverage;
that requires a deployment-owned endpoint and short-lived job token in a
separate acceptance environment.

The adapter fails closed unless it runs in a cgroup-v2 systemd service with an
empty delegated root and the process moved into a supervisor subgroup:

```systemd
[Service]
Delegate=yes
DelegateSubgroup=supervisor
MemorySwapMax=0
```

It enables and verifies the delegated CPU, memory, and process controllers,
forces rootless Podman to use cgroupfs beneath that exact root, and requests
equal memory and memory-plus-swap limits. Before exposing a sandbox on create,
replay, or attach, it proves from `/proc` and cgroupfs that the live workload is
a descendant and that the boundary has both `memory.swap.max=0` and
`memory.swap.current=0`. Missing delegation, a different cgroup layout, or a
swappable boundary stops the owned workload and rejects the operation.

- [Runner host guide](https://github.com/automata-ci/automata/blob/main/docs/platforms/arch-linux.md)
- API documentation: run `cargo doc -p automata-ci-sandbox-podman --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
