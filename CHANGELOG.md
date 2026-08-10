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
- Fail-closed configured rootless-Podman admission plus privileged static runner
  registration for bootstrap deployments without an enrollment API.
- Static x86-64 Linux archive, checksum-verifying installer, crates.io workspace,
  GHCR images, SBOMs, third-party license material, and release attestations.
- Opt-in GitHub browser login and device-flow server endpoints with
  envelope-encrypted login/provider state, hashed session credentials, fresh
  numeric membership authority, and the RBAC management HTTP API.

### Known limitations

- This bootstrap release is not production-ready and has not passed the full
  end-to-end compatibility gate.
- Signed GitHub webhooks, Check Runs, automated runner enrollment,
  managed-secret runner delivery, and complete administration UI/CLI surfaces
  are not composed.
- Prebuilt archives and release images currently target Linux x86-64; runner
  execution additionally requires the documented rootless Podman host path.

[Unreleased]: https://github.com/automata-ci/automata/commits/main
