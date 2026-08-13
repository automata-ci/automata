# Platform support

Automata separates portable control-plane behavior from operating-system
credential, filesystem, packaging, and execution adapters. A binary compiling
for a platform is not evidence that every product trust boundary is supported
there.

Automata remains bootstrap software. No public release artifact is available
for any platform, and the end-to-end compatibility gate has not passed.

## Current support

| Capability | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Build `automata` from source | Supported development path | Supported development path | Intended, not yet CI-verified |
| `automata preview` and status commands | Supported | Supported | Intended, not yet CI-verified |
| Single-machine workflow demo | Planned | Planned local evaluation path | Unsupported |
| Durable `automata server` composition | Bootstrap Linux path | Unsupported | Unsupported |
| CLI authentication and secret management | Linux Secret Service adapter | Unsupported | No supported custody adapter |
| Build and run passive `automata-runner doctor` | Supported | Supported | Intended, not yet CI-verified |
| Durable runner journal and encrypted spool | Linux adapter | Windows adapter | Unsupported |
| Execute container/action-capable jobs | Rootless Podman integration | Unsupported | Unsupported |
| Execute trusted native shell jobs | Not the initial Linux provider | Experimental Windows native provider | Unsupported |
| Prebuilt release archive or installer | Not published | Not published | Not published |

Unsupported credential-bearing and execution operations fail closed. Automata
does not fall back to plaintext credential files, ambient Docker or Podman
sockets, or a weaker isolation claim.

## Windows development surface

Install Git, rustup's 64-bit MSVC host, and the Visual Studio Build Tools
**Desktop development with C++** workload. From a reviewed source checkout,
build both commands with:

```powershell
cargo build --locked --bin automata --bin automata-runner
```

The dependency-free preview, status client, and passive diagnostics are safe
starting points:

```powershell
automata preview --listen 127.0.0.1:8080
automata admin --server-url http://127.0.0.1:8080 status
automata-runner doctor --server http://127.0.0.1:8080 --json
```

Run the local native build, preview, status, SSR, and passive-diagnostic smoke
check with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/dev/windows-smoke.ps1
```

The experimental Windows runner is a separate, explicitly configured tier. It
supports trusted `run:` steps through PowerShell Core, Windows PowerShell,
`cmd.exe`, and an optional configured Python interpreter. A per-sandbox Windows
Job Object provides assignment-before-resume, whole-process-tree termination,
and configured process, memory, and CPU limits. It does not reduce the service
account token or provide container, virtual-machine, network, or root-filesystem
isolation.

Use the Windows runner only under a dedicated non-administrative account with
administrator-provisioned restrictive ACLs. It rejects every `uses:` action,
job and service containers, owner-only file secret sources, administrator job
profiles, and POSIX shell templates. See the exact configuration and custody
requirements in the [getting-started guide](getting-started.md#windows-source-build-and-native-runner-boundary).

## Portability contract

### Portable product core

Provider-neutral domain models, workflow planning, scheduling policy, protocol
messages, HTTP applications, immutable blob contracts, and the isolated SSR
renderer should retain the same semantics on every supported control-plane
platform.

Portable code must not infer an operating-system capability from successful
compilation. It receives an explicit adapter and propagates a typed unavailable
result when that adapter is absent.

### Host security adapters

Each operating system needs reviewed implementations for:

- encrypted CLI session custody;
- secure secret-file opening and metadata validation;
- service lifecycle and process shutdown;
- certificate and private-key custody; and
- release packaging, installation, and update verification.

The intended credential adapters are Linux Secret Service, Windows Credential
Manager backed by DPAPI, and macOS Keychain. They must preserve audience
separation, exact server-origin binding, bounded reads, crash-safe activation,
and the no-plaintext-fallback contract.

Windows runner state currently relies on restrictive operator-managed ACLs.
The safe adapter rejects reparse traversal, but cannot attest DACL ownership or
single-link count. Owner-only private material therefore remains
environment-backed on Windows.

### Execution providers

Execution support is provider-specific:

- Linux rootless Podman supplies the current container and action-capable path.
- Windows native execution supplies trusted host shell steps with Job Object
  process-tree containment.
- A future Windows Hyper-V provider is required for hostile workloads.
- macOS native and Virtualization.framework providers remain design work.

A provider may advertise only capabilities it enforces and has tested. Process
containment must not be described as container or virtual-machine isolation.

## Acceptance gates

A platform progresses independently through these gates:

1. **Build:** both product commands compile without warnings for the native
   target.
2. **Portable tests:** provider-neutral unit and contract tests pass natively.
3. **Preview:** health, readiness, SSR, embedded assets, and graceful shutdown
   pass on the native host.
4. **Control plane:** secure inputs, PostgreSQL, object storage, listeners,
   authentication, and readiness pass their platform contracts.
5. **Runner diagnostic:** passive diagnostics report only proven native facts.
6. **Runner execution:** a reviewed provider passes lifecycle, capability,
   cancellation, recovery, and its claimed isolation tests.
7. **Distribution:** a native archive or installer has reproducible provenance,
   checksums, SBOMs, license material, and release smoke tests.
8. **Compatibility:** unchanged workflow fixtures pass the differential evidence
   required by the [compatibility contract](compatibility.md).

CI must name only the gate it actually enforces. The trusted Windows provider
is not evidence of hostile-workload isolation or general GitHub Actions
compatibility.

## Known work

The [Windows local evaluation design](windows-local-evaluation.md) defines a
planned loopback-only composition for one trusted repository and native runner.
It remains Planned until the complete command passes native acceptance tests;
it does not enable the durable Windows server.

The [durable Windows release roadmap](windows-release-roadmap.md) owns the
control-plane, service, installer, recovery, and publication checklist. The
immediate cross-platform backlog is:

- keep native Windows builds warning-free and expand portable test coverage
  without disabling Windows-provider tests;
- establish a native macOS build, preview, and diagnostic baseline;
- split CLI authentication transport from credential-custody adapters;
- implement Windows and macOS CLI credential custody without plaintext fallback;
- design supported control-plane secure-file adapters before enabling durable
  server composition outside Linux;
- extend trusted Windows execution only with capability-specific tests, and add
  Hyper-V isolation before accepting hostile workloads; and
- add platform-specific packaging and release evidence.

Changes to credentials, secure files, runner identity, or isolation cross trust
boundaries and require an issue and design review before implementation, as
described in [CONTRIBUTING.md](../CONTRIBUTING.md).
