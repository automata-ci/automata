# Automata React SSR UI

This directory is the build-time React + Vite boundary for Automata's web UI. It
does not contain a Node production server. Rust owns HTTP routing, authentication,
authorization, status codes, persistence, and mutations. For each request Rust
constructs a typed `RenderRequest`, invokes the embedded renderer, and returns the
complete HTML document.

All current page kinds are server rendered with meaningful content:

- `setup` renders the JavaScript-independent, one-use administrator bootstrap
  form; the host exposes it only while durable installation setup is armed.
- `repository-directory` renders the bounded repositories available under the
  viewer's current access, exact Code/Actions/Settings destinations, forward
  pagination, and its repository-neutral empty state.
- `run-list` renders filters, run data, pagination, and ordinary links.
- `run-detail` renders run metadata, compact job destinations, and finalized
  artifacts as a read-only view.
- `job-log` renders job navigation, bounded log pages, search, and stable line
  links.
- `repository-settings` renders independent run-page, job-log, and artifact
  access defaults for newly admitted runs. Existing runs keep their immutable
  access snapshot, and an update form exists only when the host supplies an
  authenticated, CSRF-protected update capability.
- `repository-secrets` renders value-free encrypted-secret metadata and exposes
  mutation forms only when the host supplies their exact capabilities.
- `user-list`, `user-detail`, `role-list`, `role-detail`, and
  `direct-binding-list` render tenant access management. Revision-bound native
  forms appear only when the host authorizes the exact member, role, permission,
  or direct-binding mutation; immutable and provider-observed records remain
  read-only.

The browser bundle hydrates the same document. JavaScript enhances the theme
toggle, in-page log filtering, and repository-settings draft and submission
states. Links, GET filters, settings forms, and RBAC management forms retain
their native behavior when JavaScript is absent or fails. There is no SPA router
and every initial page route remains a complete server-rendered document.

## Source architecture

The detailed presentation, hook, presenter, and service dependency rules are
documented in [`src/ARCHITECTURE.md`](src/ARCHITECTURE.md) and enforced by
`npm run test:architecture`.

The source tree keeps transport, view composition, presentation, and the demo
separate:

```text
src/
├── components/   reusable landmarks and presentation components
├── hooks/         React state, effects, measurement, and browser lifecycle
├── logs/          resumable transport controller and strict SSE adapter
├── pages/         thin composition containers for validated page models
├── presentation/ shared status, timing, and event copy derivation
├── presenters/    deterministic model-to-view projections
├── preview/      representative sample data, projections, and demo routing
├── services/      host protocol and mutation clients without React
├── styles/       layered tokens, layout, components, pages, and conditions
├── validation/   exact validation of the untrusted host boundary
├── viewModels/    contracts passed from behavior into presentation
└── views/         pure page and feature presentation
```

Production pages receive validated initial models and render ordinary links and
forms; they do not own generic page-data loading or know how the static demo is
routed. The job-log page replays and tails one structured stream, with
group-owned panels and in-memory search. The shared live-log package selects
advertised transports, strictly decodes SSE, advances durable checkpoints, and
reconnects through the same replay path, as specified by
[ADR 0005](../docs/architecture-decisions/0005-structured-execution-log-groups.md).
The demo owns its sample data and its small query-preserving GET adapter, and
production source never imports test fixtures. The adapter is reinstalled on hot
module replacement so routing changes do not leave a stale submit handler.
`styles.css` only declares the cascade order and imports the focused modules
documented in `src/styles/README.md`.

## Commands

Node is a build and test dependency only. Dependencies and the lockfile are pinned.

```sh
npm ci
npm run check
npm audit --audit-level=low
```

Run the component workshop locally with:

```sh
npm run storybook
```

Storybook uses the production stylesheet and typed CSF stories, includes light
and dark themes plus desktop, tablet, and mobile viewports, and runs every story
through Chromium with blocking accessibility checks. `npm run check` enforces
story coverage, executes the browser stories, and builds the static Storybook
alongside the production bundles.

Generate production-source coverage for the Vitest unit and integration suites
with:

```sh
npm run test:coverage
```

Coverage includes every TypeScript and TSX file under `src/`, including files
that no test imports, and writes reports beneath the ignored `coverage/`
directory. The terminal summary is accompanied by
`coverage/coverage-summary.json`, `coverage/lcov.info`, and the browsable
`coverage/index.html`. Reports are still written when a test fails so the
failure can be diagnosed with its partial coverage data. The build-verifier and
Playwright suites remain separate contract and browser checks; this command
does not claim to measure their execution.

The checked-in aggregate coverage floors are based on the reviewed CI-pinned
Node 24.19.0 baseline:

| Metric | Baseline | Enforced floor | Headroom |
| --- | ---: | ---: | ---: |
| Statements | 93.74% | 93% | 0.74 points |
| Branches | 84.67% | 84% | 0.67 points |
| Functions | 97.43% | 96% | 1.43 points |
| Lines | 93.91% | 93% | 0.91 points |

CI runs this threshold check on Node 24.19.0; raise the floors after reviewed
coverage improvements, and lower them only with a new reproducible baseline and
an explicit justification. These aggregate floors are a regression guard, not
a substitute for reviewing per-file gaps.

For the interactive static demo, run the Vite development server and open the
printed local URL. Changes hot-reload in the browser:

```sh
npm run dev
```

The demo is explicitly marked as sample data and does not claim that its
workflow runs were executed. Repository, branch, and commit links point to real
allowlisted GitHub destinations; artifact downloads remain unavailable because
the static site has no authenticated backend. The demo requires JavaScript,
while the production application remains server-rendered. The preview can be
built and reviewed locally without adding a non-critical publication lane to
pull-request CI.

The browser suite uses Chromium to exercise the populated and empty repository
directory, the full run-list → run-summary → job-log path, both read-only
repository settings views, and all five tenant access-management views. For
each page in light and dark mode at desktop, tablet, and mobile sizes, it first
asserts the requested theme and canvas, visible and non-overlapping shell
landmarks, viewport bounds, layout stability, document overflow, and browser
runtime health. The same matrix then writes 72 PNG review artifacts under
`dist/preview/screenshots/`:

```sh
npx --no-install playwright install chromium
npm run screenshots
```

Capture settings are deterministic: Chromium runs with fixed viewports, UTC,
`en-US`, reduced motion, disabled screenshot animations, static preview data,
and a wait for the locally bundled icon font. It owns its preview server instead
of reusing an ambient process and serves the build from `/automata/`, matching
the GitHub Pages project-site topology. The preview build verifier rejects
root-relative executable/style URLs, missing assets, unexpected output, and
other subpath-breaking output before the browser suite starts, then checks the
exact non-empty PNG set.

The PNGs are human-review artifacts, not automated pixel-diff baselines. This is
intentional: committing 72 browser-rendered goldens would make routine Chromium
and font rasterization changes noisy while obscuring meaningful regressions.
The deterministic DOM, layout, theme, and runtime contracts are the automated
gate; screenshots preserve broad visual review without pretending that file
creation alone is an assertion. Each matrix case captures in its failure path,
so visual diagnostics remain available locally and are not presented as
executed-run evidence. The suite also checks native demo
routing, keyboard focus, mobile disclosures, forced colors, reduced motion,
theme persistence, and browser runtime errors.

Production cleanup is scoped to `dist/client` and `dist/ssr`; it never removes
an in-progress preview build or screenshot run. `npm run clean` remains the
explicit whole-output cleanup command.

Tests are kept outside production sources: pure contract and URL tests live in
`tests/unit`, end-to-end SSR/hydration behavior lives in `tests/integration`,
component browser and accessibility checks live in colocated Storybook stories,
browser behavior and captures live in `tests/visual`, and adversarial host
requests live in `tests/fixtures`. `npm run check` enforces architecture and
coverage, runs unit, integration, Storybook, and build-verifier tests, then
type-checks, builds, and verifies the Storybook and production outputs:

```text
dist/
├── client/
│   ├── manifest.json
│   └── assets/
│       ├── entry-client-<hash>.js
│       └── entry-client-<hash>.css
└── ssr/
    └── renderer.mjs
```

`dist/ssr/renderer.mjs` is one bundled ESM file built with Vite's `webworker` SSR
target and no external packages. Its stable host-facing export is:

```ts
render(serializedRequest: string): string
```

The result always starts with `<!doctype html>` and contains the whole document.
The build verifier imports the emitted bundle, enforces ECMAScript-module
syntax, rejects static module edges, ambient CommonJS references, and known Node
loader escape paths, and performs a render smoke test. It is a closure check for
trusted bundler output, not a sandbox for hostile JavaScript or string-evaluation
analysis.

The checked-in Vite server bundle is compiled into a WASI Preview 2 component;
Rust embeds that component and the hash-addressed client assets. At runtime the
host supplies those same-origin paths through `RenderRequest.host.assets` and
invokes the component with a fresh, resource-limited Wasmtime store. Host-owned
locale, CSP nonce, and executable asset paths stay outside the page model and
cannot be selected by route data. Display timestamps are already formatted in
the page model so server and browser rendering never diverge because of timezone
or locale differences. User-controlled values are escaped by React, and the
hydration JSON additionally escapes HTML delimiter characters.

## Runtime boundary

The production binary does not ship Node or a JavaScript sidecar. The generated
component contains the JavaScript runtime and renderer behind a narrow WIT
interface, with no inherited filesystem, sockets, environment, subprocesses, or
standard streams. The Rust host enforces input/output, aggregate memory, table,
instance, host-resource, fuel, concurrency, and wall-time limits. The component,
client assets, lockfiles, provenance, and CycloneDX inventory are reproducibly
generated and checked by CI before static-musl packaging.

The serialized interface is versioned (`schemaVersion: 1`) and validated deeply
with exact shapes and explicit size limits before rendering or hydration. Every
internal link and form action must be a safe same-origin route path. Explicit
source links must instead be exact canonical `https://github.com` targets bound
to the page's repository, commit, or source ref; unsupported providers and
target shapes fail closed. Script and CSS assets must be rooted, fragment-free
paths with the expected file type. Adding a route means adding a discriminated
`PageModel` variant, its validator, and complete rendering in `App`; unknown
variants fail rather than falling back to an empty client shell.

## Reusable package boundary

`npm run build` also assembles the private, registry-neutral `@automata/ui`
package beneath `dist/package`. Its deliberately small public surface contains
the existing Core page renderer, the shared application shell, the theme
control and bootstrap script, host-neutral provider connection and repository
selection components, the page-model types, the resumable live-log controller,
and a stable compiled stylesheet at `@automata/ui/styles.css`. A separate host
can render its own page content inside `Shell`, compose provider controls around
the shared presentation, and supply its own authenticated live-log ticket
provider. The package does not contain an identity provider, Cloud API
knowledge, Cloud-only pages, or a plugin system.

`npm run verify:package` renders consumer-owned content through the packaged
shell, checks the compiled stylesheet, creates the npm archive twice, and
requires byte-identical tarballs with a bounded file set. The package remains
`private` and version `0.0.0`: those guards intentionally defer its final name,
versioning policy, registry, and release mechanism. `npm pack` can still produce
a local archive for integration work without allowing accidental publication.
