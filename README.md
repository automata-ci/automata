# Automata

Automata is a self-hostable, horizontally scalable execution platform for
GitHub Actions workflows. Its compatibility mode is intended to run existing
`.github/workflows` and actions without repository-specific rewrites.

The project is at the bootstrap stage. Compatibility claims are accepted only
when the same workflow revision has been compared against GitHub Actions; an
unimplemented feature is reported as incompatible and is never silently
ignored.

## Distribution model

Automata produces two product executables:

- `automata` — workflow ingestion, planning, scheduling, results, GitHub
  integration, fleet control, API, server-rendered UI, and a `gh`-style
  administration CLI.
- `automata-runner` — capability discovery, leases, action execution,
  sandbox and container providers, logs, and crash reconciliation.

Linux release artifacts are statically linked with musl. First-party adapters
are compiled in and selected by configuration. Optional third-party providers
communicate over versioned out-of-process protocols rather than Rust dynamic
libraries. Each deterministic archive includes CycloneDX inventories for both
executables, the embedded WASI renderer, and its production React runtime. It
also carries SHA-256-indexed, verbatim third-party license and NOTICE/copyright
texts generated offline from the exact Cargo and npm packages selected by the
checked-in lockfiles and review policy. The generator fails when a shipped
component lacks license material, when an allowlist drifts, or when an audited
fallback changes. NOTICE coverage is necessarily limited to files actually
published in those locked packages, so dependency-update review must also check
for upstream-only notice obligations.

## Non-negotiable design rules

- Existing GitHub workflows remain unchanged in compatibility mode.
- Automata's own ordinary GitHub Actions CI is its first end-to-end workload.
- All first-party Rust crates forbid `unsafe` code.
- PostgreSQL owns durable coordination; S3-compatible storage owns immutable
  blobs. Object storage is not used as a lock service.
- Labels and runner groups are routing policy. Typed capabilities express OS,
  architecture, resources, container support, and isolation.
- Every attempt is leased and fenced. A stale runner may finish locally but
  cannot commit a result.
- A job never receives the host Podman socket or control-plane credentials.
- Every UI route is rendered on the server with React and Vite. Browser code
  may progressively enhance a page but cannot supply its essential content.

See [the architecture](docs/architecture.md) and
[compatibility contract](docs/compatibility.md). The ordered work, acceptance
gates, and `world-engine` rollout are tracked in the
[implementation plan](docs/implementation-plan.md).

## Development

The Rust workspace is pinned by `rust-toolchain.toml` and uses the lockfile:

```console
export TMPDIR="$PWD/target/task-tmp/local"
install -d -m 0700 -- "$TMPDIR"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Project build, test, regeneration, and probe tooling must keep scratch data
under the ignored repository `target/` tree. It does not use the host `/tmp`,
which may be shared, inode-constrained, or mounted with unsuitable execution
policy on CI and bare-metal runner hosts.

Run the initial process-level smoke test with:

```console
cargo run --bin automata -- server --listen 127.0.0.1:8080
cargo run --bin automata-runner -- doctor --server http://127.0.0.1:8080 --json
```

The production integration stack will use rootless Podman, PostgreSQL, and
RustFS locally. Provider prerequisites are runtime capabilities, not linked
dependencies of either Automata executable.

## License

[MIT](LICENSE) © 2026 Alexander Dzhoganov.
