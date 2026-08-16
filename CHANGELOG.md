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
- Internal `LocalSnapshot` foundation for tracked and non-ignored live-worktree
  source. It hashes the exact deterministic archive consumed by the existing
  bounded workflow discovery, pins filesystem ancestors without following
  links, normalizes tracked symlinks from Git mode, rejects Windows reparse
  points, sparse or assume-unchanged index state, and bounded
  Unicode-normalized portable path-graph aliases, supports exactly one explicit
  `.github/workflows` or `.ci/workflows` namespace, and exposes no partial
  admission, execution, GitHub authentication, or Check Run path.

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
