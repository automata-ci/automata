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
cargo test -p automata-ci-github --test live_repository_snapshot --locked -- --ignored

# S3/RustFS contracts. Set AUTOMATA_TEST_S3_ENDPOINT,
# AUTOMATA_TEST_S3_BUCKET, AUTOMATA_TEST_S3_ACCESS_KEY,
# AUTOMATA_TEST_S3_SECRET_KEY, and the service's exact
# AUTOMATA_TEST_S3_KMS_KEY_ID. The results contracts also need
# AUTOMATA_TEST_DATABASE_URL.
cargo test -p automata-ci-blob-s3 --test rustfs_contract --locked -- --ignored --test-threads=1
cargo test -p automata-ci-action --test live_github_rustfs --locked -- --ignored --test-threads=1
cargo test -p automata-ci-action-github --test live_checkout_pipeline --locked -- --ignored --test-threads=1
cargo test -p automata-ci-results-github --test rustfs_results --locked -- --ignored --test-threads=1
cargo test -p automata-ci-results-github --test cache_rustfs --locked -- --ignored --test-threads=1
cargo test -p automata-ci-workflow-service --test live_admission --locked -- --ignored --test-threads=1

# Official Node client compatibility. Set AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE
# and AUTOMATA_TEST_ACTIONS_CACHE_MODULE to the exact modules named by the tests.
cargo test -p automata-ci-results-github --test http_compatibility --locked -- --ignored --test-threads=1
cargo test -p automata-ci-results-github --test cache_http --locked -- --ignored --test-threads=1

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
`cargo-llvm-cov` release:

```console
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.8.7 --locked
CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  ./scripts/ci/run-rust-coverage.sh coverage/rust-ordinary ordinary
```

The command writes `summary.json`, `coverage.lcov`, and `manifest.json`. The
output directory must be inside the repository and ignored by Git, as the
documented `coverage/` and `target/` locations are. The
manifest names requested and not-requested test bundles plus each requested
bundle's service requirements, so an ordinary report cannot be mistaken for
service-complete workspace coverage. CI retains these files as the
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
stale instrumentation cannot enter a report. A nonblocking lock prevents two
cooperating Linux/util-linux coverage runners from sharing that fixed target;
it does not lock source files against editors. Reports are staged, the workspace
fingerprint is checked again after collection, and the manifest is published
last as the completion marker; a concurrent source edit leaves no final
artifact. Checker exit status 1 is reserved for an ordinary coverage regression:
the runner independently verifies a complete failed-guard manifest and both
report hashes before publishing diagnostics. Checker I/O errors and partial or
malformed manifests fail closed without a published artifact.

The ordinary regression guard is deliberately narrower than a raw workspace
percentage. After the policy's renderer and generated-source exclusions, the
reviewed report measured 64.36% of in-scope compiled production lines because
53,999 PostgreSQL-owned adapter lines had no service profiles. The committed
policy inventories those global exclusions and assigns the exact PostgreSQL
paths to that service bundle; the remaining ordinary-owned source measured
82.97%, with an 82% floor and 0.97 percentage points of headroom. The guard also
requires at least 172,000 measured lines—more than 98% of that reviewed
denominator—so a broad exclusion cannot make the percentage pass. S3, Podman,
and live-client source stays in
ordinary scope where deterministic tests cover it; their external test bundles
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

The complete filesystem, Podman, nftables, and provider checks are maintained
in the [runner bootstrap guide](../crates/automata-ci-runner/config/README.md)
and [Arch Linux host guide](platforms/arch-linux.md). Update those operator
contracts with any admission change; do not duplicate their configuration in
this contributor guide.

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

## Local installation preflight

The first cross-platform local-installation slice is a read-only host check for
x86-64 Linux, Apple Silicon macOS, and x86-64 Windows. It requires a local Linux
Docker Engine with the supported API and matching architecture, Docker Compose
plugin version 2.20.0 or newer, resolves a dedicated root below the native
platform user-state directories, and rejects broad roots and a Unix root
process:

```console
cargo run --locked -p automata-ci -- local doctor
cargo run --locked -p automata-ci -- local doctor --json
```

The command does not create the state directory or any container resources.
`local up` and the worker composition remain planned; follow the
[local installation and deployment roadmap](maintainers/roadmaps/local-installation.md) for
their merge and host-qualification gates.

## Local PostgreSQL and RustFS

Start the pinned development services:

```console
podman-compose --file deploy/dev/compose.yaml up --detach
podman-compose --file deploy/dev/compose.yaml ps
```

Set the integration-test environment:

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
cargo test -p automata-ci-blob-s3 --test rustfs_contract --all-features --locked -- --ignored
./scripts/ci/verify-postgres-version.sh
./scripts/ci/run-postgres-tests.sh
```

The runner always removes the exact namespace it owns. Use a fresh namespace
for every invocation when a PostgreSQL service is reused. Individual tests may
install the shared schema-local `TestClock` to advance lease and retry horizons
without sleeping for wall time.

These credentials are local-only. Stop the services with:

```console
podman-compose --file deploy/dev/compose.yaml down
```

Named volumes survive `down`; see the [local infrastructure guide](../deploy/dev/README.md)
before removing development data.

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
container smoke check. The result is
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
deploy/       Local durable-service definitions and firewall examples
docs/         User, operator, architecture, and compatibility documentation
images/       Immutable runner environment profiles
scripts/      CI, development, and renderer tooling
ui/           React/Vite source and the embedded renderer build
```

The workspace has many crates to keep trust and provider boundaries explicit,
but only `automata` and `automata-runner` are distributed as product commands.
Their crates.io packages are `automata-ci` and `automata-ci-runner`; internal
packages use the same `automata-ci-*` namespace.
