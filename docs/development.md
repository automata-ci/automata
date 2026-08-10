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

## Runner capability admission

`automata-runner doctor --active` is an ambient operator diagnostic. It finds
`podman` through the invoking process's `PATH` and uses diagnostic scratch
settings, so a successful doctor run is not evidence that production startup
will admit the configured provider. It can return raw Podman failure detail;
do not use it as an in-process readiness check or forward its output outside
the operator trust domain.

`automata-runner run` constructs one validated Podman configuration and fails
before starting any listener or control session unless both checks succeed:
the required nftables modules must be loaded or loadable from the running
kernel's dependency index, and the active lifecycle must pass against the exact
configured binary, cleared `HOME`/`PATH`/`XDG_RUNTIME_DIR`/`TMPDIR` environment,
state-root probe paths, and `NetworkPolicy`. Production requires a nonzero
effective UID and does not invoke `podman info`. Exercise both policy branches
in focused work: `PrivateEgress` requires a non-internal network and `Disabled`
requires `--internal`.

The active lifecycle checks the running executable as a static ELF, writes its
exact bytes as the only file in a private rootfs, and runs it with
`--rootfs <path>:O`. It verifies the source descriptor/name binding and full
bytes before and after start, network identity and policy, exclusive container
attachment, loopback readiness, ownership, exact-ID cleanup, and post-delete
absence. The overlay keeps runtime changes out of the source; an unconfirmed
container retains its lowerdir rather than invalidating storage that may still
reference it.
It does not prove profile-image existence or manifest conformance,
cgroup/resource enforcement, privilege or root-filesystem policy, or the
optional job-scoped Docker API. Keep the configured Podman binary and every
directory in its `PATH` administrator-controlled and immutable to runner jobs.
Production admits the exact root-owned Podman, conmon, OCI runtime, init,
seccomp, cleanup, and closed seven-entry helper inputs with
non-group/world-writable ancestry. It requires the Podman home, runtime,
temporary, probe-parent, generated configuration, hooks, CDI, and engine roots
to be runner-owned, non-symlink, mode 0700 paths beneath trusted ancestry. The
hooks and CDI directories must remain empty; `$HOME/.config/containers` and
`$HOME/.docker` must be absent or empty and private, and `$HOME/.dockercfg`
must be absent. The default `/etc/containers/certs.d`,
`/usr/share/containers/certs.d`, and `/etc/docker/certs.d` registry-client
certificate trees must likewise be absent or exactly empty, so nested builds
cannot borrow ambient client keys. Each one-file rootfs child is mode 0711
beneath the private probe parent. The admitted snapshot is revalidated before every
runner-initiated Podman spawn and every authorized request to a long-lived job
Docker service. Podman/conmon's stopped-container cleanup re-exec inherits the
fixed environment inside the trusted administrator/runtime boundary and does
not pass through the runner guard. This is filesystem identity and ownership
evidence, not a byte attestation. Job sandboxes never receive these host paths.

## Frontend

Node is a build and test dependency, not a production dependency. The built
React renderer and browser assets are embedded in `automata`.

```console
cd ui
npm ci
npm run check
npm audit --audit-level=low
```

If a frontend change intentionally updates the embedded renderer, use the
locked profile launcher. It runs regeneration and asset verification inside
the locked, reproducible profile environment:

```console
./scripts/ui/reproduce-renderer-in-profile.sh
```

Read [the UI guide](../ui/README.md) before changing the render contract or
adding a page kind.

## Local PostgreSQL and RustFS

Start the pinned development services:

```console
podman-compose --file deploy/dev/compose.yaml up --detach
podman-compose --file deploy/dev/compose.yaml ps
```

Set the integration-test environment:

```console
export AUTOMATA_TEST_DATABASE_URL='postgresql://automata:automata-local-only@127.0.0.1:5432/automata'
export AUTOMATA_TEST_S3_ENDPOINT='http://127.0.0.1:9000/'
export AUTOMATA_TEST_S3_BUCKET='automata-dev'
export AUTOMATA_TEST_S3_ACCESS_KEY='automata-local'
export AUTOMATA_TEST_S3_SECRET_KEY='automata-local-secret-change-me'
```

The S3 contract creates the test bucket when necessary and verifies immutable
publication before other suites use it:

```console
cargo test -p automata-ci-blob-s3 --test rustfs_contract --all-features --locked -- --ignored
cargo test -p automata-ci-store --tests --all-features --locked -- --ignored --test-threads=1
cargo test -p automata-ci-auth-postgres --tests --all-features --locked -- --ignored --test-threads=1
cargo test -p automata-ci-runner-auth-postgres --tests --all-features --locked -- --ignored --test-threads=1
cargo test -p automata-ci-secret-postgres --tests --all-features --locked -- --ignored --test-threads=1
cargo test -p automata-ci-results-github --test postgres_artifacts --all-features --locked -- --ignored --test-threads=1
```

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
