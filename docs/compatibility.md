# GitHub Actions compatibility contract

Automata compatibility mode accepts standard GitHub workflow and action files.
It does not add YAML keywords or require expressions that branch on the
orchestrator. A repository is compatible only when the same immutable source
revision runs with equivalent observable semantics on GitHub Actions and
Automata.

## Reference and evidence

Each release records the upstream `actions/runner` revision against which it was
developed. The open runner's parser, schema, expression behavior, fixtures, and
protocol documentation are treated as a reference implementation. Automata
ports behavior into safe Rust and keeps provenance for imported MIT fixtures.

The initial G1 baseline, reviewed on 2026-08-07, is
[`actions/runner` v2.336.0](https://github.com/actions/runner/releases/tag/v2.336.0)
at commit
[`98aabcd429c4e8402406c56ce2d26387fed3b9ce`](https://github.com/actions/runner/commit/98aabcd429c4e8402406c56ce2d26387fed3b9ce).
Its bundled JavaScript-action runtime is Node.js 24.18.0. This pin is a
semantic research and differential-test baseline, not a dependency in either
Automata binary. Advancing it requires a reviewed compatibility-delta record
and rerunning the conformance suite; a floating upstream branch is never used
as evidence.

The v2.336.0 delta also makes background-step control, the
`GITHUB_ARTIFACTS` file command, `$self` repository-action references, and the
effective cache-mode environment part of the tracked compatibility surface.
They are not claimed by G1 until their differential fixtures pass.

A conformance run records:

- source workflow/action digests and event payload digest;
- expanded jobs, matrices, dependencies, conditions, and concurrency groups;
- step order, outcome, conclusion, outputs, and registered post actions;
- command files, annotations, masked logs, services, and dynamic ports;
- attempt, rerun, cancellation, timeout, and artifact/cache behavior; and
- environment and negotiated runner capability fingerprints.

Differential comparison may normalize only inherently volatile data such as
opaque IDs, timestamps, temporary paths, signed URLs, and credentials. Any
semantic difference is a compatibility failure. Unsupported syntax or runtime
requirements fail before scheduling with a source span and machine-readable
reason; Automata never silently ignores an option.

## Compatibility surface

The required surface includes triggers and filters, reusable workflows,
expressions and coercions, matrices, DAGs, defaults, permissions, environments,
secrets, outputs, status functions, implicit success guards, concurrency,
reruns, file commands, shell selection, JavaScript/composite/container actions,
pre/main/post lifecycle, job and service containers, labels, runner groups,
artifacts, cache APIs, results APIs, OIDC, and the relevant GitHub REST surface.

Hosted labels map to immutable, fingerprinted environment profiles. They are
not generic aliases. A provider may advertise a profile only after its image and
behavior probes pass the corresponding conformance suite.

## GitHub-owned boundary

GitHub's public APIs do not allow a third party to insert arbitrary native
Actions workflow-run, job, log, or artifact records. Automata therefore reports
GitHub Check Runs and provides an Actions-compatible API/results facade plus
its own SSR run UI. Runtime environment variables and narrowly scoped client
routing make workflows use that facade without source changes. API behavior
outside the implemented compatibility surface is proxied to GitHub using a
job-scoped token.

Secrets must be configured in Automata because GitHub does not expose their
values. Automata OIDC follows GitHub-compatible claim semantics but uses its own
issuer and signing keys, so cloud trust policies must explicitly trust it.

## Dogfood gate

The first end-to-end workflow is Automata's normal
`.github/workflows/ci.yml`, not a special smoke workflow. Generation zero is
built by GitHub Actions from a reviewed commit. It runs the exact same workflow
bytes and repository SHA through Automata to produce generation one. Results
are compared before a canary promotion; a workflow can never replace the
control plane currently executing it.

New runtime features enter that workflow as they land: static distribution,
artifacts, caches, matrices, reusable workflows, concurrency cancellation,
services, Podman-backed Docker compatibility, and React/Vite SSR. GitHub remains
the differential oracle until the full suite is stable, and continues to run
periodically afterward to detect upstream semantic drift.
