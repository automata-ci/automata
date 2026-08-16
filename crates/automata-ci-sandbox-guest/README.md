# Automata sandbox guest

`automata-ci-sandbox-guest` provides the bounded, versioned command transport
used inside Automata Kubernetes Pods, macOS virtual machines, and
Hyper-V-isolated Windows containers. Kubernetes packages the executable in a
dedicated guest image and copies it into each workload Pod; the macOS template
and Windows runner image bake the reviewed executable into their immutable
artifacts.

Protocol v5 keeps command arguments, environment values, and file contents out
of Kubernetes Pod specifications, exec request URLs, and container-runtime
command lines. Unix guests use the persistent authenticated socket lifecycle;
the `stdio-once` transport handles one framed request over anonymous standard
input while its caller owns lifecycle, replay, and recovery fencing. Protocol
v1 through v4 traffic is rejected rather than migrated. Persistent Unix guests
reserve replay capacity before execution, retain every accepted result for the
guest lifetime, and reject a new operation identifier before execution once the
fixed 256-entry or byte bound is full.

Protocol upgrades are lockstep artifact changes. A v5 host binary must be
deployed with rebuilt Kubernetes guest images, Windows runner images, macOS VM
templates, and the macOS vsock bridge. An older guest is intentionally rejected
instead of being interpreted as v5.

## Durable file protocol

The current protocol has two narrow operations for engine-managed configuration:

- `atomic_commit_file` replaces one bounded absolute path using a
  compare-and-swap expectation: either `absent` or the exact SHA-256 digest of
  the current bytes. Its result is `committed`, `already_current`, or
  `conflict`. Desired bytes are checked first, so retrying the same request
  after an ambiguous transport result is idempotent. A conflict leaves the
  destination unchanged. `committed` is returned only after the replacement
  and its containing directory have been synchronized on Unix. Native Windows
  guests reject this operation without mutation; local Docker Desktop uses the
  same Linux helper image on Windows and macOS as it does on Linux.
- `read_optional_file` returns bounded file bytes or a typed missing result.
  Only an operating-system `NotFound` result is reported as missing; other I/O
  failures remain sanitized operation failures. Unix reads are
  descriptor-anchored, do not follow symlinks, and require a regular file.

The one-shot transport requires clean standard-input EOF before dispatching an
`atomic_commit_file` request. Trailing bytes therefore fail before mutation.
Paths, file bytes, and expected state remain redacted from debug output.
After dispatch, a transport failure or sanitized operation failure can be
post-rename ambiguity. The caller must start a fresh helper and use
`read_optional_file` to inspect the destination, but matching bytes alone are
not durability proof. It must issue a fresh `atomic_commit_file` for those same
desired bytes and require `already_current` or `committed`; both successful
outcomes synchronize the exact file and parent directory before acknowledging
success.

`write_file` and `read_file` implement the sandbox provider copy contract;
durable engine configuration uses only the operations above.

## Local Docker protected client

The evaluation-only local Docker provider runs the guest as the container's
actual PID 1 with Docker init disabled, no capabilities, built-in seccomp, and
`no-new-privileges`. Before admitting workload traffic, PID 1 copies its exact
executable into a fixed `tmpfs` mounted `rw,exec,nosuid,nodev` with exact size,
owner, group, and mode. A distinct one-shot UID seals a root-owned seed into the
fixed client name and changes the directory to mode `0510`. PID 1 verifies the
held seed inode, exact client bytes and metadata, seed absence, mount type, and
sealed directory through one peer-credential-authenticated handshake.

Every provider operation then executes the sealed client as `65532:65532` and
requires a complete framed response over the abstract broker socket. The
capability-free UID 0 workload cannot traverse the directory, alter or execute
the client, assume the client UID, inspect the non-dumpable PID 1 executable, or
deliver a terminating signal to namespace PID 1. A setup ambiguity is accepted
only after the protected client returns the exact `Ready` response; otherwise
the provider destroys the exact container and recreates instead of resealing or
adopting it.

## Helper image contract

The multi-architecture Linux helper image is `scratch`-based and runs as
`65532:65532`. It contains `/var/lib/automata-local` owned by that UID/GID with
mode `0700`. Docker can therefore initialize a fresh, explicitly mounted named
volume from the image directory and the non-root helper can commit the local
desired spec without a root startup step. The image deliberately does not
declare a `VOLUME`; the caller must select and mount the exact managed volume.

Local orchestration must use an architecture-compatible registry-qualified
image digest that is already present at the selected daemon. Helper execution
must not pull implicitly or fall back to UID 0. The intended container envelope
uses a read-only root filesystem, no network, all capabilities dropped, and
`no-new-privileges`, with only the exact config volume writable.

Build the image from the repository root so the workspace lockfile and member
manifests are available. Pushing to a test repository is the portable way to
obtain a registry `RepoDigest` (some local image stores assign one earlier) and
keep the exact digest loaded in the selected daemon. For example, with an
already configured local test registry:

```bash
export AUTOMATA_SANDBOX_GUEST_LIVE_DOCKER_HOST=unix:///var/run/docker.sock
export AUTOMATA_GUEST_TEST_REPOSITORY=localhost:5000/automata/sandbox-guest
docker --host "$AUTOMATA_SANDBOX_GUEST_LIVE_DOCKER_HOST" build \
  --file crates/automata-ci-sandbox-guest/Containerfile \
  --tag "$AUTOMATA_GUEST_TEST_REPOSITORY:protocol-v5" .
docker --host "$AUTOMATA_SANDBOX_GUEST_LIVE_DOCKER_HOST" push \
  "$AUTOMATA_GUEST_TEST_REPOSITORY:protocol-v5"
export AUTOMATA_SANDBOX_GUEST_LIVE_IMAGE="$(docker \
  --host "$AUTOMATA_SANDBOX_GUEST_LIVE_DOCKER_HOST" image inspect \
  --format '{{index .RepoDigests 0}}' \
  "$AUTOMATA_GUEST_TEST_REPOSITORY:protocol-v5")"
```

This repository does not yet publish a default sandbox-guest image. The test
therefore never builds or pulls implicitly.

An ignored live test exercises the image contract against an explicit Docker
daemon. It uses a daemon-generated volume name plus a cryptographic ownership
label, revalidates the unattached volume before non-force removal, and lets
Docker auto-remove each unnamed one-shot helper. Run it with the preloaded
digest:

```bash
export AUTOMATA_SANDBOX_GUEST_LIVE_DOCKER=1
export AUTOMATA_SANDBOX_GUEST_LIVE_DOCKER_HOST=unix:///var/run/docker.sock
export AUTOMATA_SANDBOX_GUEST_LIVE_IMAGE='ghcr.io/automata-ci/automata-ci-sandbox-guest@sha256:<64-lowercase-hex>'
docker --host "$AUTOMATA_SANDBOX_GUEST_LIVE_DOCKER_HOST" image inspect \
  "$AUTOMATA_SANDBOX_GUEST_LIVE_IMAGE"
cargo test -p automata-ci-sandbox-guest --test behavior \
  opt_in_docker_fresh_named_volume_is_writable_by_nonroot_guest \
  -- --ignored --exact --nocapture
```

Operators must build and publish every guest-bearing image or VM template from
reviewed repository source, then configure the runner with an
architecture-compatible digest pin. The Kubernetes image contract is
described by the
[`automata-ci-sandbox-kubernetes` contract](../automata-ci-sandbox-kubernetes/README.md#guest-image-contract).
The Windows host and image acceptance requirements are in the
[Windows isolation plan](../../docs/platforms/windows.md).
