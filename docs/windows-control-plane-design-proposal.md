# Durable Windows control-plane design proposal

Status: **Proposed in [issue #16](https://github.com/automata-ci/automata/issues/16)**.
This document does not authorize credential, filesystem, service-identity, or
public support changes. Those changes begin only after maintainers approve the
design issue, as required by `CONTRIBUTING.md`.

The [Windows release roadmap](windows-release-roadmap.md) tracks implementation
and acceptance after design approval. Issue #13 owns the trusted native runner;
this proposal owns the separate durable control-plane boundary.

## Problem

Automata can build and serve its dependency-free preview on Windows, and its
trusted native runner can execute shell jobs against a control plane. The
complete `automata server` deployment is not supported on Windows because its
credential-bearing file inputs, static runner registration, CLI session
custody, service identity, lifecycle, installation, and recovery contracts do
not have reviewed Windows implementations.

Operators in Windows-only environments therefore need a Linux host for the
control plane even when PostgreSQL and S3-compatible storage are already
available as external services. Merely starting the current server with
process-environment secrets would not establish a supportable Windows service:
it would leave private-key custody, ACL ownership, service shutdown, upgrade,
and recovery requirements undefined.

## Desired outcome

Publish a signed Windows Server 2025 x86-64 release in which:

- `automata server` runs as a dedicated non-interactive Windows service;
- PostgreSQL and S3-compatible object storage remain external dependencies;
- the control plane and runner use separate service identities and state roots;
- TLS, GitHub, database, object-store, session, and secret-encryption material
  is loaded through explicit reviewed custody adapters;
- static runner registration and every file-backed private input use a Windows
  secure-file adapter or remain unavailable;
- the service survives process restart and machine reboot without duplicate
  execution or silent state loss;
- installation, upgrade, rollback, repair, and uninstall have tested MSI
  contracts; and
- exact signed artifacts include checksums, SBOMs, license material, and build
  provenance.

The first release targets Windows Server 2025 x86-64. Windows 11 x86-64 is a
development and evaluation host, not a production server target. Windows ARM64,
Hyper-V hostile-workload execution, containers, and general GitHub Actions
compatibility are outside this proposal.

## Proposed product topology

The default installation keeps control and execution identities separate:

```text
GitHub and operators
        |
        v
AutomataControl Windows service
   |                 |
PostgreSQL       S3-compatible storage
        |
        | outbound mTLS runner session
        v
AutomataRunner Windows service
        |
trusted native shell provider
```

The installer does not bundle or silently install PostgreSQL or object storage.
Running control and runner services on one machine may be allowed for trusted
evaluation, but is not the recommended production topology.

## Trust and compatibility considerations

### Identities

The release needs separate least-privilege identities for the control plane and
runner. The design must decide between installer-created virtual service
accounts, operator-provisioned accounts, and optional group Managed Service
Accounts. The runner remains non-administrative. A workflow process retains the
runner service account token and must not be able to read control-plane state.

### Credential custody

The current Linux operator CLI invokes Secret Service through `secret-tool` and
keeps a private process lock beneath the user's runtime directory. Windows needs
an adapter with the same origin, audience, size, ambiguity, deletion, and
no-plaintext-fallback contracts. The proposed candidate is Windows Credential
Manager with user-scoped DPAPI protection; review must confirm record limits,
identity behavior, and corruption handling.

The service needs explicit sources for TLS identities, database credentials,
S3 credentials, GitHub App credentials, browser and CLI session keys, Results
signing keys, runner CAs, and secret-encryption keyrings. Environment references
may remain an explicit supervisor-owned source, but they are not a substitute
for defining service installation and secret rotation. Certificate Store and
service-scoped DPAPI references are proposed additions.

### Secure files

The Unix server opens each path component without following symlinks and checks
file type, owner, permissions, size, and, where required, single-link status.
The Windows adapter must provide an equivalent capability contract using
Windows handles, reparse-point rejection, owner SID and DACL inspection, link
count, bounded reads, exclusive locking, atomic replacement, and flush behavior.
It must reject drive-relative paths, alternate data streams, device namespaces,
and ambiguous path forms.

Safe stable Rust does not expose the complete required metadata. The design
must select a narrowly scoped reviewed safe dependency or wrapper. First-party
crates continue to forbid `unsafe`.

### Storage and protocols

The proposal does not require a runner protocol, PostgreSQL schema, S3 object
format, JobIR, or workflow compatibility change. Existing durable authorities,
fencing, immutable object references, and mTLS separation remain unchanged.
Any discovered protocol or schema change requires separate review.

### Service and distribution

Ctrl-C handling is not a Windows service lifecycle. The service adapter must
handle Service Control Manager stop and preshutdown notifications, bounded
graceful shutdown, recovery actions, sanitized Event Log output, and reboot
reconciliation. Secrets must not appear in service command lines, `ImagePath`,
installer logs, registry strings, Event Log messages, or diagnostics.

The release requires separately signed control-plane and runner MSI packages.
Configuration and state survive upgrade and uninstall by default; destructive
purge is explicit. Downgrade across an incompatible schema fails before service
replacement.

## Current platform-boundary inventory

| Location | Classification | Current behavior | Required decision |
| --- | --- | --- | --- |
| `src/cli/mod.rs` | Credential custody | Selects fixed unsupported auth/secret adapters outside Unix | Define Windows CLI adapter selection |
| `src/cli/credential_store.rs` | Credential custody and process lock | Linux `secret-tool`, Unix file descriptors, runtime-directory lock | Define Credential Manager/DPAPI and Windows process lock |
| `src/cli/auth.rs` | Portable transport plus custody construction | Constructs Linux Secret Service adapter | Inject a platform custody adapter |
| `src/cli/secret.rs` | Portable secret API plus custody construction | Constructs Linux Secret Service adapter | Inject the same platform custody adapter |
| `src/server/config.rs` | Service secret source and secure file | Environment source works; non-Unix file source returns `FileSecurity` | Define Windows service sources and secure bounded files |
| `src/server/static_registration.rs` | Privileged secure file | Returns `UnsupportedPlatform` outside Unix | Define SID/DACL/reparse/link-count contract |
| `src/shutdown.rs` | Service lifecycle | Ctrl-C only outside Unix | Define SCM stop and preshutdown adapter |
| `src/server/composition.rs` tests | Test fixture security | Applies owner-only mode only on Unix | Add native Windows composition fixtures |
| `src/server/github_oidc.rs` tests | Test fixture security | Applies owner-only mode only on Unix | Add Windows custody fixtures |
| `src/server/github_provider*_tests.rs` | Test fixture security | Unix-only private-file setup | Separate portable parsing from native custody tests |
| `Cargo.toml` Unix target dependencies | Platform dependency | `rustix` is Unix-only | Select reviewed Windows dependencies only after design approval |

The runner journal, encrypted spool, and trusted native execution provider have
Windows adapters under issue #13. They are dependencies of the release but do
not satisfy control-plane custody or service requirements.

## Acceptance evidence

A design-approved implementation is complete only when all of the following
pass on clean Windows Server 2025 x86-64 machines:

1. Both product binaries build without warnings from a locked source checkout.
2. MSI installation creates separate least-privilege services and restrictive
   state roots without placing secrets in process arguments or logs.
3. The control plane starts against external PostgreSQL and S3-compatible
   storage and reports dependency-specific readiness.
4. A real workflow is admitted, leased over mTLS, executed by the Windows
   runner, published, cleaned, and reconciled through the production paths.
5. Service restart and machine reboot during admission, leasing, execution,
   publication, and cleanup produce no duplicate execution or silent loss.
6. ACL, reparse-point, hard-link, alternate-data-stream, path-namespace, and
   sharing-violation tests fail closed.
7. Upgrade, rollback, repair, uninstall, and explicit purge behavior pass on
   clean and previously configured machines.
8. Executables and MSI packages have valid Authenticode signatures, trusted
   timestamps, checksums, SBOMs, license material, and provenance bound to the
   exact release commit.

Passing these gates supports the durable Windows control-plane claim only. It
does not make trusted native process containment a hostile-workload sandbox or
add unsupported action and container semantics.

## Alternatives considered

### Keep the control plane Linux-only

A Linux control plane with outbound Windows runners remains the simplest and
recommended near-term deployment. It avoids Windows custody and service work,
but does not serve operators whose supported server estate is Windows-only.
This remains a supported topology even if the proposal is implemented.

### Require environment secrets for every Windows service input

The current parser can load bounded environment references on Windows. Making
that the entire custody design would leave installer, service identity,
rotation, diagnostic, and recovery behavior undefined and would not enable
static registration. Environment references may remain explicit sources, but
cannot replace the secure adapter and service contracts.

### Bundle PostgreSQL and object storage

Bundling reduces initial setup but expands patching, backup, upgrade, licensing,
and data-loss responsibilities. The first release keeps both dependencies
external and verifies connectivity and readiness instead.

### Run control and runner under one service identity

A shared identity simplifies installation but lets trusted workflow processes
reach control-plane material. The proposal requires separate identities and
state roots.

### Weaken Unix file checks on Windows

Accepting ordinary readable files would create platform-dependent plaintext and
path-redirection fallbacks. Unsupported custody must remain unavailable until a
Windows adapter proves the required contract.

## Decisions requested in design review

- Is Windows Server 2025 x86-64 the only initial production target?
- Are virtual service accounts sufficient, or is gMSA required initially?
- Which Credential Manager and DPAPI scopes satisfy CLI and service custody?
- Is Windows Certificate Store support required in the first release?
- Which safe dependency may expose handle, SID, DACL, reparse, and link-count
  evidence?
- Are environment-backed private service inputs supported in production, and
  under which supervisor contract?
- Must static runner registration ship in the first Windows release?
- Which MSI technology and signing service satisfy repository supply-chain
  policy?
- What upgrade and schema-downgrade window is supported?

## AI assistance

OpenAI assisted with repository boundary inventory and preparation of this
issue-ready proposal. The submitter must review and understand the complete
proposal before filing it or treating it as design authority.
