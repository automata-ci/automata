# Development

This guide covers the normal contributor loop. Production deployment and
runner-host provisioning have different requirements; see the
[documentation index](README.md) for those paths.

## Toolchains

The Rust workspace is pinned by `rust-toolchain.toml` and `Cargo.lock`. A normal
Rust-only change needs Git, rustup, and native build tools.

Frontend changes additionally need Node.js 24.19.0 and npm. Local integration
tests need rootless Podman, `podman-compose`, PostgreSQL client tools, and
OpenSSL. Static Linux distribution builds also need musl and ELF tooling.

The native Rust workspace, control plane, and PostgreSQL contract suite are
supported on Apple Silicon macOS. The complete gate also requires the pinned
Node.js 24.19.0 release used by compatibility fixtures. The database scripts
require Bash 4 or newer; Apple's `/bin/bash` 3.2 is too old. A headless Homebrew
setup can provide the required shell, PostgreSQL 18 server, and client:

```console
brew install bash postgresql@18
brew services start postgresql@18
export PATH="/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$HOME/.cargo/bin:$PATH"
export AUTOMATA_PSQL_BINARY=/opt/homebrew/opt/postgresql@18/bin/psql
```

Run `./scripts/ci/run-macos-checks.sh` from the repository root for the complete
non-service macOS gate. It rejects an unpinned Node version, keeps all test
scratch space under a short, trusted `target/` ancestry that also respects
Darwin Unix-socket limits, formats, lints, tests, and documents every workspace
target other than the intentionally Linux-only `automata-ci-service-proxy`, then
builds all three release Swift executables used by the native VM provider.

The secret-safe PostgreSQL launcher discovers that Apple Silicon Homebrew path
and the Intel Homebrew prefix when no override is set. Keep the explicit
absolute override for nonstandard installations. The repository's ordinary
Linux CI service is patch-pinned to PostgreSQL 18.4; local integration tests
accept PostgreSQL 18 or newer, while `verify-postgres-version.sh` requires an
explicit `AUTOMATA_EXPECTED_POSTGRES_VERSION_NUM` when testing another reviewed
patch release.

Keep generated scratch data under the ignored `target/` tree. The project does
not use the host `/tmp`, which may be shared, inode-constrained, or mounted with
an unsuitable execution policy.

```console
export TMPDIR="$PWD/target/task-tmp/local"
install -d -m 0700 -- "$TMPDIR"
```

The release installer preserves an explicit absolute `TMPDIR`. Without one, it
creates an owner-only download directory below `XDG_RUNTIME_DIR`,
`XDG_CACHE_HOME`, or `$HOME/.cache`, in that order; it never defaults to the
host `/tmp`.

Local repository snapshots are also fail-closed. Review and stage the intended
paths in the default Git index, then run
`scripts/dev/create-integration-snapshot.sh target/integration/source`. The
destination must not already exist. The script refuses alternate indexes,
unstaged tracked changes, and nonignored untracked paths, so it cannot silently
capture a working-tree credential. It publishes the staged tree atomically
beneath `target/` or leaves the requested output absent.

## Fast contributor loop

Run formatting and the tests closest to your change first:

```console
cargo fmt --all -- --check
cargo test -p automata-ci --locked
cargo test -p automata-ci-runner --locked
```

Development and test profiles keep file/line information for first-party
crates, while dependencies omit debug metadata. On Linux hosts with LLVM's
linker installed, the CI-equivalent faster linker can be enabled per command:

```console
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS='-C link-arg=-fuse-ld=lld' \
  cargo test -p automata-ci --locked
```

CI runs repository verification, Rust linting, documentation, dependency
auditing, coverage, renderer tests, and distribution construction as parallel
gates. Rust jobs share content-addressed compiler outputs through `sccache` and
cache the locked Cargo registry plus pinned CI tools; raw `target/` directories
are deliberately not cached because they are large and path-sensitive.

Before opening a pull request, run the workspace checks used by CI:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
```

All first-party Rust crates forbid `unsafe` code.

### Test design

Test observable contracts rather than implementation shape. Prefer exact typed
errors, state transitions, durable custody, side-effect counts, and retry
identity over `is_ok`, `is_err`, debug-string, or source-text assertions. Keep
compile-time trait assertions at module scope; do not wrap them in empty runtime
tests. A failure-path test should also prove which calls or mutations did *not*
occur.

Coordinate concurrent tests with barriers, notifications, or Tokio's paused
clock. Wall-clock timeouts are watchdogs, not assertions, and must leave enough
headroom for a loaded parallel CI worker. Use source inspection only when the
source artifact itself is the contract, such as a migration or generated-file
provenance check. Every ignored integration test must name its external
prerequisite and have a corresponding CI or documented manual lane.

### Opt-in test lanes

The PostgreSQL CI lane executes every database-only ignored target in one
shared build environment. Current-schema tests clone one job-scoped,
pre-migrated PostgreSQL template into an isolated database and run with bounded
parallelism; the migration inventory contract stays in the ordinary Rust test
lane. The remaining ignored integration targets are explicit operator lanes:

```console
# Public GitHub compatibility.
cargo test -p automata-ci-provider-github --test live_repository_snapshot --locked -- --ignored

# S3/RustFS contracts. Set AUTOMATA_TEST_S3_ENDPOINT,
# AUTOMATA_TEST_S3_BUCKET, AUTOMATA_TEST_S3_ACCESS_KEY,
# AUTOMATA_TEST_S3_SECRET_KEY, and the service's exact
# AUTOMATA_TEST_S3_KMS_KEY_ID. The results contracts also need
# AUTOMATA_TEST_DATABASE_URL.
cargo test -p automata-ci-blob-s3 --test blob_s3 --locked -- rustfs_contract:: --ignored --test-threads=1
cargo test -p automata-ci-action --test live_github_rustfs --locked -- --ignored --test-threads=1
cargo test -p automata-ci-action-actions --test live_checkout_pipeline --locked -- --ignored --test-threads=1
cargo test -p automata-ci-runner-results --test rustfs_results --locked -- --ignored --test-threads=1
cargo test -p automata-ci-runner-results --test cache_rustfs --locked -- --ignored --test-threads=1
cargo test -p automata-ci-workflow-service --test live_admission --locked -- --ignored --test-threads=1

# Official Node client compatibility. Set AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE
# and AUTOMATA_TEST_ACTIONS_CACHE_MODULE to the exact modules named by the tests.
cargo test -p automata-ci-runner-results --test http_compatibility --locked -- --ignored --test-threads=1
cargo test -p automata-ci-runner-results --test cache_http --locked -- --ignored --test-threads=1

# Rootless Podman contracts. Set AUTOMATA_LIVE_ROOTLESS_PODMAN=1 and
# AUTOMATA_LIVE_ROOTLESS_BUILDX=1. Configure the AUTOMATA_PODMAN_TEST_*
# variables declared by live_rootless.rs, including a digest-pinned
# AUTOMATA_PODMAN_TEST_BUILDKIT_IMAGE, and the AUTOMATA_TEST_* paths required
# by the runner active-probe test.
cargo test -p automata-ci-sandbox-podman --test live_rootless --locked -- --ignored --test-threads=1
cargo test -p automata-ci-runner --locked \
  configured_rootless_lifecycle_matches_both_production_network_policies -- \
  --ignored --test-threads=1
```

On Apple Silicon, `./scripts/ci/run-macos-integration-checks.sh` composes the
six RustFS contracts above with the exact artifact/cache client real-store
acceptance. In addition to the database and S3 variables, set the three pinned
action roots and module paths named by
`exact_client_real_store.rs`: `AUTOMATA_TEST_UPLOAD_ARTIFACT_ACTION_ROOT`,
`AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE`,
`AUTOMATA_TEST_DOWNLOAD_ARTIFACT_ACTION_ROOT`,
`AUTOMATA_TEST_ACTIONS_DOWNLOAD_ARTIFACT_MODULE`,
`AUTOMATA_TEST_CACHE_ACTION_ROOT`, and
`AUTOMATA_TEST_ACTIONS_CACHE_MODULE`. The gate checks the platform and pinned
Node release, bounds every test to one thread, and always removes its complete
PostgreSQL namespace. `--plan` prints the credential-free command matrix.

The coverage runner checks the filtered runner probe listing against exact test
identities in the policy and against every ignored function in its source file,
so adding an ignored test outside the current module filter fails closed.

The three ignored metrics schema printers are maintenance commands rather than
coverage-bearing tests. Invoke them deliberately with `--ignored --nocapture`
when reviewing a manifest change; the non-ignored schema assertions remain the
regression contracts.

### Coverage

Coverage is a diagnostic for finding unexercised behavior; it does not replace
the PostgreSQL, RustFS, Podman, compatibility, or security contract lanes. The
Rust report uses the pinned toolchain's LLVM tools and a reviewed
`cargo-llvm-cov` release. The driver supports Linux and macOS with Python 3.9
or newer:

```console
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.8.7 --locked
CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  ./scripts/ci/run-rust-coverage.sh coverage/rust-ordinary ordinary
```

The command writes `summary.json`, `coverage.lcov`, and `manifest.json`. The
output directory must be inside the repository and ignored by Git, as the
documented `coverage/` and `target/` locations are. The
manifest names the runner platform, requested and not-requested test bundles,
and each requested bundle's service requirements, so an ordinary report cannot
be mistaken for service-complete workspace coverage. CI retains these files as the
`rust-coverage-ordinary` artifact. It also binds the report to Git HEAD and a
reproducible SHA-256 content digest of every tracked or unignored workspace
path, and records SHA-256 hashes for both report formats. A separately named
metadata-sensitive state token detects an edit that restores the original
bytes during collection; it is provenance for that run, not a reproducible
content identity. The checker requires the JSON and LCOV source sets and
per-file line totals to agree exactly. It also validates each LCOV `DA` record's
syntax and line-number uniqueness, and requires at least one `DA` record when
`LF` is positive. LLVM region accounting means the number of `DA` records, and
the subset with a nonzero execution count, need not equal `LF` or `LH`; those
declared totals remain cross-checked against the JSON export instead. The
detailed LCOV bytes are integrity-bound by their recorded hash and the runner's
locked, staged publication rather than being derivable from the summary JSON.

Instrumented artifacts live under `target/llvm-cov-target`, isolated from
ordinary Cargo fingerprints. Allow disk space for a separate all-feature
workspace build; the runner cleans that coverage target before collection so
stale instrumentation cannot enter a report. A nonblocking POSIX advisory lock
prevents two cooperating Linux or macOS coverage runners from sharing that
fixed target; it does not lock source files against editors. Reports are staged,
the workspace fingerprint is checked again after collection, and the manifest
is published last as the completion marker; a concurrent source edit leaves no
final artifact. Checker exit status 1 is reserved for an ordinary coverage regression:
the runner independently verifies a complete failed-guard manifest and both
report hashes before publishing diagnostics. Checker I/O errors and partial or
malformed manifests fail closed without a published artifact.

On macOS the driver also exports a short, owner-only temporary directory under
`target/`. This keeps instrumented Unix-domain sockets below the platform path
limit while preserving the private-directory requirement of CLI credential
locks; callers do not need to override `TMPDIR`.

The ordinary regression guard is deliberately narrower than a raw workspace
percentage. The policy inventories global exclusions and assigns the exact
PostgreSQL paths to that service bundle. Linux and macOS compile different
conditional production paths, so each platform has a separately reviewed
ordinary baseline while retaining the same source-ownership rules. The Linux
baseline is 202,158 of 246,784 lines (81.92%), with an 81% floor and a 246,000
line minimum. The macOS baseline is 191,348 of 247,854 lines (77.20%), with a
76.25% floor and a 247,000 line minimum. The macOS ordinary command excludes
only the explicitly Linux-only service-proxy package. Both denominator checks
retain more than 99% of their reviewed source sets, so a broad exclusion cannot
make the percentage pass. S3, Podman, and live-client source stays in ordinary
scope where deterministic tests cover it; their external test bundles
supplement that evidence.

Run a service test bundle when all of that bundle's prerequisites are available:

```console
./scripts/ci/run-rust-coverage.sh coverage/rust-postgres postgres
./scripts/ci/run-rust-coverage.sh coverage/rust-s3 s3
./scripts/ci/run-rust-coverage.sh coverage/rust-podman podman
./scripts/ci/run-rust-coverage.sh coverage/rust-github-live github-live
./scripts/ci/run-rust-coverage.sh coverage/rust-node-live node-live
```

Each bundle fails closed when its documented environment is absent. To merge
profiles on a host that has several prerequisites, name all bundles in one
invocation, for example `ordinary postgres`. Merged and service-only reports
are report-only: service hits cannot be used to satisfy the ordinary baseline.
Run `ordinary` alone to enforce the regression guard. PostgreSQL CI remains a
separate behavior gate; its normal test results are not silently attributed to
the ordinary coverage artifact.

These names are test bundles, not isolated service dimensions. In particular,
the `s3` bundle also needs PostgreSQL and public GitHub access; those
prerequisites can contribute partial profiles without executing the complete
`postgres` or `github-live` bundles. The manifest records that distinction.

The generated protobuf module and renderer-generated Rust are excluded from
the report, not from compilation or tests. Renderer tests remain in their
separate resource-heavy CI job; this workflow makes no renderer coverage
claim. Review per-file and per-crate gaps and ratchet the committed policy only
from a reproducible ordinary-bundle report.

## Runner capability admission

`automata-runner doctor --active` checks the ambient host and the `podman` found
on the caller's `PATH`. Use it for diagnosis, not readiness: production startup
repeats admission against the exact configured binary, environment, state
roots, and network policy before it contacts the control plane.

Runner-focused changes should test both `PrivateEgress` and `Disabled` network
policies, failed cleanup, changed filesystem metadata, stale leases, and process
restart. A successful lifecycle probe proves that the configured provider can
create, inspect, and destroy its test sandbox. It does not prove profile-image
conformance, resource enforcement, or service-container support.

The complete filesystem, Podman, networking, and provider checks are maintained
in the [runner bootstrap guide](../crates/automata-ci-runner/config/README.md).
Update that product contract with any admission change; do not duplicate its
configuration in this contributor guide.

## Frontend

Node is a build and test dependency, not a production dependency. The built
React renderer and browser assets are embedded in `automata`.

```console
cd ui
npm ci
npm run check
npm run test:coverage
npm audit --audit-level=low
```

`test:coverage` measures every TypeScript and TSX source file, including files
that the test graph never imports, and writes its reports under the ignored
`ui/coverage/` directory. Frontend CI runs this command and enforces aggregate
floors of 93% statements, 84% branches, 96% functions, and 93% lines. Those
floors retain 0.99–1.29 percentage points of headroom under the reviewed
CI-pinned Node 24.19.0 baseline; see the
[UI guide](../ui/README.md#commands) for the baseline and ratcheting policy.

If a frontend change intentionally updates the embedded renderer, use the
locked profile launcher. It runs regeneration and asset verification inside
the locked, reproducible profile environment:

```console
./scripts/ui/reproduce-renderer-in-profile.sh
```

Read [the UI guide](../ui/README.md) before changing the render contract or
adding a page kind.

## Local installation preflight and sealed custody

The cross-platform local-installation preflight is a read-only host check for
x86-64 Linux, Apple Silicon macOS, and x86-64 Windows. It requires a local Linux
Docker Engine 28.0.0 or newer with API 1.48 or newer and matching architecture,
Docker Compose plugin version 2.33.1 or newer, and rejects a Unix root process:

```console
cargo run --locked -p automata-ci -- local doctor
cargo run --locked -p automata-ci -- local doctor --json
```

Doctor does not create host state or container resources. It reports
the selected Docker context and pins all daemon probes to that context's exact
validated local endpoint.

On x86-64 Linux, the production `local init` consumer is a separate mutating
boundary:

```console
cargo run --locked -p automata-ci -- local init \
  --state-directory /var/lib/automata-local/default \
  --catalog-source file:/srv/automata-release/local-installation-catalog.json
cargo run --locked -p automata-ci -- local up \
  --state-directory /var/lib/automata-local/default
cargo run --locked -p automata-ci -- local status \
  --state-directory /var/lib/automata-local/default --json
cargo run --locked -p automata-ci -- local down \
  --state-directory /var/lib/automata-local/default
cargo run --locked -p automata-ci -- local reset \
  --state-directory /var/lib/automata-local/default --yes
```

It accepts only an x86-64 Linux Engine at
`unix:///var/run/docker.sock`, an explicit canonical absolute state directory,
and an explicit local release-catalog file. The catalog-selected candidate must
be its exact no-follow regular sibling. Init verifies the canonical catalog and
candidate structure/digests, but the operator remains responsible for selecting
authenticated release evidence. It pulls or imports the exact image set,
creates/adopts the immutable identity and twelve owner-specific persistent
volumes, retains one-time certificate custody, runs one fixed networkless
materializer, and seals the immutable epoch plus canonical desired intent.
Replay reattests the same custody and fails closed on missing or conflicting
records/resources.

Init stops after sealing material and desired intent. Catalog/current-epoch
authentication computes one fixed synthetic Compose/expected-topology fixture
in memory to bind the production renderer, but init does not generate or persist an
installation-specific Compose document, invoke a Compose operation, or start a
control plane, relay, bootstrap, database, object store, or runner. `local up`
reattests the sealed epoch and exact Docker/Compose authority, renders the
canonical topology, and synchronously converges dependencies, bootstrap,
control, relay, and runner services. `local down` synchronously removes that
replaceable topology while preserving sealed custody, persistent data, and
images. Status/reset may render the expected topology read-only for comparison.
Repeating either convergence command re-inspects and reconciles current Engine
and Compose truth.

Lifecycle convergence requires empty daemon-wide `log-opts`, empty bridge
`default-network-opts`, and empty `default-ulimits` as trusted host
prerequisites because `/info` does not completely attest them. The post-create
inspection catches any injected container log option, bridge option, or ulimit;
the operation then fails closed and leaves its stopped exact-ID lock as sticky
recovery evidence. All eight trusted fixed lifecycle services and the fixed
custody helpers explicitly use `userns_mode: host` to preserve sealed host
ownership. The Engine relay additionally needs that namespace for bounded
root-owned-socket bootstrap, while untrusted `LocalDocker` jobs inherit the
required daemon-default user-namespace remap.

A stopped exact-ID lifecycle lock is sticky interruption evidence, so ordinary
`init`, `up`, and `down` refuse it. Restart Docker Engine so the accepting daemon
generation can be proven absent, then rerun the intended command with
`--recover-stopped-lock`; that
explicitly authorizes removal of only the reattested stopped ID before normal
convergence. A live, drifting, or unknown holder is never recovered this way.

`local status` opens only existing custody under a shared, nonrepairing lock and
distinguishes recorded sealed, exact running, lifecycle-recovery, and reset
states from canonical host and live Engine evidence. It does not run a volume
inspector. `local reset` never prompts and requires `--yes`; it requires an
authority-bound canonical epoch plus complete exact Engine custody, then
reconciles its self-contained durable deletion transaction despite
cancellation. Safe malformed or missing non-authority material/certificate
records do not strand cleanup, but copied/pre-guard, conflicting canonical,
mismatched, unexpectedly managed, or foreign-attached custody is refused before
mutation. Images, the state directory, and its original operation lock remain.
Status and reset connect directly to the fixed Docker socket; they do not depend
on the Docker CLI, current context, `DOCKER_API_VERSION`, or Compose plugin.
Reset does not require retained image representations to remain present. Follow
the [local installation and deployment roadmap](maintainers/roadmaps/local-installation.md)
for the remaining host-qualification gates.

The local-source path seals tracked and non-ignored live bytes through pinned,
no-follow ancestor handles and feeds the exact digest-bound archive through the
shared workflow discovery policy. Git mode normalizes tracked symlinks across
native Unix links and placeholders. Sparse and assume-unchanged index flags
cannot hide live bytes, ignored paths are classified in bounded batches, and
portable path identity uses a bounded Unicode-normalized full-case-folded
component trie. The current checkpoint fails closed on Windows until exact
native mutation evidence is qualified. Its adversarial fixture suite is
available with:

```console
cargo test --locked -p automata-ci-local snapshot::tests
```

Use the same source path without starting Docker or mutating Git:

```console
cargo run --locked -p automata-ci -- local check
cargo run --locked -p automata-ci -- local check .github/workflows/ci.yml \
  --input target=staging --json
```

`local check` captures the archive once and accepts only direct canonical
`.github/workflows/*.{yml,yaml}` members. When more than one workflow exists,
pass its exact repository-relative path; filename, stem, display-name, and
`.ci/workflows` fallbacks do not exist. The root must explicitly declare
`workflow_dispatch`. Reachable reusable calls are recompiled only from members
of that same archive, while remote, dynamic, missing, and cyclic calls fail
closed. The shared traversal validates typed inputs, secret forwarding,
outputs, propagation, and expansion bounds. Reports contain external secret
and variable names plus closed built-in requirements such as `github_token`,
but never input values, secret values, absolute paths, archive bytes, or a
repository identity. `github_token` is not a promptable user secret, and this
read-only checkpoint does not claim it can supply one for execution.

The command is independent of `local doctor`, Docker, network access, and a
GitHub token. It never admits, schedules, or runs work, contacts GitHub, or
creates a Check Run; local admission and execution remain later roadmap
checkpoints.

The ignored fixed-relay Local Docker conformance fixture requires an existing
installation anchor, the explicit `/run/automata-engine/docker.sock` relay,
already-present digest-pinned Linux job and sandbox-guest images, the exact
daemon-local imported service-proxy identity, and the desired-plan-bound,
externally provisioned Results transit and target. The
relay must front rootful Docker with daemon-default user-namespace remapping
enabled. All eight trusted fixed lifecycle services and the fixed custody
helpers use the host user namespace to preserve sealed host ownership; the
Engine relay additionally needs it for socket bootstrap. The untrusted test
jobs inherit the daemon remap. The built-in seccomp and
private-cgroup-namespace security options must be reported, AppArmor and
SELinux must be disabled, every required resource controller must be available,
and daemon-wide `log-opts`, bridge `default-network-opts`, and `default-ulimits`
must be empty. The fixture verifies the realized exact log/network/ulimit
contracts and custody-only rollback. Its network gate
also requires `results.automata.invalid:8081` to reach only the configured
numeric Results target while external DNS and public-IP egress fail. Rootless
Docker and multi-range UID/GID maps are intentionally rejected. The
fixture verifies the job's nonzero host mappings, attenuated UID-0 identity and
empty Linux capability sets, shell and JavaScript execution, and the protected
tmpfs client. It then removes only the revalidated sibling containers it
created:

```console
AUTOMATA_LOCAL_DOCKER_INSTALLATION='evaluation' \
AUTOMATA_LOCAL_DOCKER_INSTALLATION_ID='6e561f8b-9098-418d-b573-d82f5c73006e' \
AUTOMATA_LOCAL_DOCKER_JOB_IMAGE='registry.example/automata/job@sha256:<64-lowercase-hex>' \
AUTOMATA_LOCAL_DOCKER_GUEST_IMAGE='registry.example/automata/sandbox-guest@sha256:<64-lowercase-hex>' \
AUTOMATA_LOCAL_DOCKER_RESULTS_PROXY_CONFIG_IMAGE_ID='sha256:<64-lowercase-hex>' \
AUTOMATA_LOCAL_DOCKER_RESULTS_PROXY_MANIFEST_IMAGE_ID='sha256:<64-lowercase-hex>' \
AUTOMATA_LOCAL_DOCKER_DESIRED_PLAN_SHA256='<64-lowercase-hex>' \
AUTOMATA_LOCAL_DOCKER_RESULTS_TRANSIT_NETWORK_ID='<64-lowercase-hex>' \
AUTOMATA_LOCAL_DOCKER_RESULTS_CONTAINER_ID='<64-lowercase-hex>' \
AUTOMATA_LOCAL_DOCKER_RESULTS_ADDRESS='10.91.0.2' \
cargo test --locked -p automata-ci-local \
  'local_docker::tests::fixed_relay_live_shell_and_javascript_conformance' \
  -- --ignored --exact --nocapture
```

## External integration-test services

Database and object-storage integration lanes use services managed outside the
repository. Automata does not provide or mutate a local infrastructure stack.
Provision compatible PostgreSQL and S3 endpoints, then set the test environment:

```console
export AUTOMATA_TEST_DATABASE_URL='postgresql://automata:automata-local-only@127.0.0.1:5432/automata'
export AUTOMATA_TEST_DATABASE_NAMESPACE="local_$(date +%s)_$$"
export AUTOMATA_TEST_S3_ENDPOINT='http://127.0.0.1:9000/'
export AUTOMATA_TEST_S3_BUCKET='automata-dev'
export AUTOMATA_TEST_S3_ACCESS_KEY='automata-local'
export AUTOMATA_TEST_S3_SECRET_KEY='automata-local-secret-change-me'
export AUTOMATA_TEST_S3_KMS_KEY_ID='default'
```

The S3 contract creates the test bucket when necessary and verifies immutable
publication before other suites use it:

```console
cargo test -p automata-ci-blob-s3 --test blob_s3 --all-features --locked -- rustfs_contract:: --ignored
./scripts/ci/verify-postgres-version.sh
./scripts/ci/run-postgres-tests.sh
```

On macOS, run the block from [Toolchains](#toolchains) first. If the installed
PostgreSQL patch is not CI's pinned 18.4, set
`AUTOMATA_EXPECTED_POSTGRES_VERSION_NUM` to that reviewed server's exact
`SHOW server_version_num` value before running the version verifier.

The runner always removes the exact namespace it owns. Use a fresh namespace
for every invocation when a PostgreSQL service is reused. Individual tests may
install the shared schema-local `TestClock` to advance lease and retry horizons
without sleeping for wall time.

The example credentials are local-only. Service lifecycle and data cleanup
remain the responsibility of the external test environment.

## Static Linux distribution

The release pipeline builds two statically linked musl executables and packages
their SBOMs and license material. The scripts are intentionally separate so
each supply-chain step can fail closed:

```console
export AUTOMATA_EXPECTED_VERSION="$(./scripts/ci/workspace-version.sh)"
export AUTOMATA_EXPECTED_GIT_SHA="$(git rev-parse --verify 'HEAD^{commit}')"
export AUTOMATA_BUILD_GIT_SHA="$AUTOMATA_EXPECTED_GIT_SHA"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"

./scripts/ci/build-static-musl.sh
./scripts/ci/verify-static-musl.sh
./scripts/ci/generate-sboms.sh
./scripts/ci/prepare-third-party-license-sources.sh
./scripts/ci/generate-third-party-licenses.sh
./scripts/ci/package-static-musl.sh
```

This path requires the pinned Node/npm versions, `cargo-cyclonedx` 0.5.9, musl
build tools, `readelf`, and Docker or Podman for the separate static-release
container smoke check. Static verification also checks public local up/down and
the exact hidden lifecycle command surface in both the host executable and its
scratch image. The result is
`target/distribution/automata-x86_64-unknown-linux-musl.tar.gz` plus its
checksum. Test its installer contract with:

```console
bash scripts/ci/tests/install.test.sh
bash scripts/ci/tests/container-context.test.sh
```

Building an archive does not publish a crate, release, or container image. See
the [release guide](releasing.md) for the protected tag workflow and its
one-time registry setup.

## Repository map

```text
crates/       Rust libraries and the two product executables
docs/         User, operator, architecture, and compatibility documentation
images/       Product packaging, helper images, and execution profiles
scripts/      CI, development, and renderer tooling
ui/           React/Vite source and the embedded renderer build
```

The workspace has many crates to keep trust and provider boundaries explicit,
but only `automata` and `automata-runner` are distributed as product commands.
Their crates.io packages are `automata-ci` and `automata-ci-runner`; internal
packages use the same `automata-ci-*` namespace.
