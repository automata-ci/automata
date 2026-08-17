# Changelog

Notable user-visible changes are recorded here. This project follows the
structure of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Bootstrap `automata` control-plane/administration command and
  `automata-runner` execution-host command.
- Loss-aware GitHub Actions workflow parsing and planning, durable PostgreSQL
  coordination, S3-compatible immutable blobs, mTLS runner control, Results and
  artifact protocol foundations, and a server-rendered preview UI.
- Fail-closed configured rootless-Podman admission plus one-use, group-scoped
  runner enrollment with runner-local key generation and audited certificate
  issuance.
- Static x86-64 Linux archive, checksum-verifying installer, crates.io workspace,
  GHCR image publication, SBOM generation, third-party license collection, and
  release-attestation automation.
- Opt-in GitHub browser login and device-flow server endpoints with
  envelope-encrypted login/provider state, hashed session credentials, fresh
  numeric membership authority, and the RBAC management HTTP API.
- Hosted delegated-actor reads for authorized repository directories, workflow
  runs, run details, durable job-log snapshots, and direct live-log tickets,
  plus delegated workflow dispatch with Core-owned mutable-ref resolution and
  exact operation replay fencing.
- Configured signed GitHub webhook ingress, public and private source delivery,
  fenced Check Runs, scoped App credentials, and lease-bound repository
  authority.
- Results artifacts, CacheService v2 current/default-branch lookup, immutable
  numeric run aliases, typed dispatch-input components, and value-level output
  sensitivity.
- Read-only `automata local doctor` preflight for the initial x86-64 Linux,
  Apple Silicon macOS, and x86-64 Windows host tuples, a local Linux Docker
  Engine, and Docker Compose plugin 2.20.0 or newer. Docker daemon probes are
  pinned to the exact endpoint resolved from the context selected first;
  stable JSON schema 3 and human output report its bounded name. The internal
  adapter can strictly inspect or create-and-adopt a repository-agnostic
  installation identity anchor without exposing a product mutation command.
- Evaluation-only fixed-relay Local Docker runner execution on Linux. Runner
  schema 6 binds the private provider to an exact existing installation anchor,
  already-present digest-pinned guest and Results-proxy images, and an exact
  pre-provisioned Results transit/target. Each job receives only a deterministic
  internal network and fixed-port credential-free proxy, with no public egress
  or external DNS. Jobs receive no host bind, Engine socket, or per-job volume;
  a protected tmpfs client performs
  each bounded guest operation once, while durable replay remains host-owned.
  The rootful relay must attest daemon-default user-namespace remapping, and
  its architecture must exactly match the runner inventory. Every sandbox
  proves a single nonzero UID/GID host mapping. Its administrator is
  intentionally UID 0 with all Linux capability sets empty, not a promise of
  `chown`, identity switching, or other POSIX capabilities. This adds no
  `automata local run` lifecycle command.
- Read-only `automata local check [WORKFLOW]` over a private, bounded snapshot
  of tracked and non-ignored live-worktree source. It hashes the exact
  deterministic archive consumed by shared workflow discovery, pins filesystem
  ancestors without following links, normalizes tracked symlinks from Git mode,
  rejects sparse or assume-unchanged index state and portable path-graph
  aliases, and accepts only direct `.github/workflows/*.{yml,yaml}` members. The
  optional selector is one exact canonical archive path, and the selected root
  must declare `workflow_dispatch`. Reachable reusable workflows must be local
  members of the same snapshot; remote, dynamic, missing, cyclic, or invalid
  calls fail closed. The shared compiler and reusable-call traversal validate
  typed inputs, secrets, outputs, propagation, and resource bounds. Human and
  JSON reports contain only value-free external credential names and closed
  built-in requirements such as `github_token`, never values, absolute paths,
  archive bytes, or repository identity. Windows source capture remains closed
  until exact native mutation evidence is qualified. The command is independent
  of `local doctor`, Docker, the network, and GitHub tokens, and performs no
  admission, scheduling, execution, or Check Run operation.
- Exact private-CA HTTPS trust for S3-compatible storage and a hidden,
  current-only `automata internal object-store ensure-bucket` image command.
  Server, initializer, and runner use closed bounded credential/trust
  configuration and the production AWS SDK client path; runner product schema
  6 requires the same explicit trust choice. Config and SDK clients are one
  inseparable store, canonical private-CA bytes and signing usage fail closed,
  connected-store diagnostics expose no bound state, validated transport is
  one closed security mode, and bucket creation is region-correct, idempotent,
  conflict-reverified, and bounded by one total deadline.
- Sandbox specifications now require one closed runner-custody variant across
  every provider; job custody includes a mandatory non-zero durable slot.

### Changed

- GitHub Actions cache eviction now durably reclaims unreachable S3 blocks with
  crash-safe, replica-safe exact-object garbage collection.

- `automata-runner enroll` now requires one explicit `--token-source` selector:
  `file:ABSOLUTE_PATH`, `env:NAME`, or `stdin`. The ambient environment/stdin
  fallback and former `--token-file` option were removed; enrollment tokens now
  share one canonical, redacted generation, validation, and digest contract.
- Job-log visibility now follows the repository publication policy after the
  runner's mandatory secret masker. Public repositories can therefore expose
  redacted logs without exposing readable runtime authority; artifact audience
  remains independently constrained.
- Sandbox cancellation now crosses provider boundaries as an explicit
  `Active | Terminate` disposition. `Terminate` authorizes provider-specific
  termination handling when an adapter reaches a cancellation checkpoint; it
  does not prove remote work quiesced or a durable operation cancelled. That
  requires proving the exact sandbox absent.
- Expired active runner leases now commit blob-free, database-authoritative
  failure evidence. Logical jobs, workflow runs, concurrency groups, and
  provider checks therefore always reach a terminal state after runner loss.
- PostgreSQL product connections now accept one exact `postgresql://` TCP URL
  with explicit host, port, user, non-empty password, and database. Query and
  fragment options, socket paths, `.pgpass`, ambient `PG*` configuration, and
  the `postgres://` alias are rejected. Transport is closed to Web PKI
  verify-full, an explicitly additive private-CA verify-full union, or
  literal-loopback plaintext. Domain adapters are imported from their owning
  crates; the former `automata-ci-postgres` compatibility namespaces were
  removed, and that crate now owns shared integration-test support only.

### Known limitations

- This bootstrap release is not production-ready and has not passed the full
  end-to-end compatibility gate.
- Automated runner certificate rotation and lifecycle administration,
  managed-secret runner delivery, workload OIDC, and several workflow semantics
  remain unsupported end to end.
- No public archive, crate, or product image has been published. Planned static
  archives and images target Linux x86-64; runner execution also requires the
  documented rootless Podman host path.

[Unreleased]: https://github.com/automata-ci/automata/commits/main
