# Automata React SSR UI

This directory is the build-time React + Vite boundary for Automata's web UI. It
does not contain a Node production server. Rust owns HTTP routing, authentication,
authorization, status codes, persistence, and mutations. For each request Rust
constructs a typed `RenderRequest`, invokes the embedded renderer, and returns the
complete HTML document.

Both implemented page kinds are server rendered with meaningful content:

- `run-list` renders filters, run data, pagination, and ordinary links.
- `run-detail` renders run metadata, jobs, steps, artifacts, and ordinary POST
  forms carrying a CSRF token.

The browser bundle hydrates the same document. JavaScript currently adds only a
confirmation prompt to forms marked with `data-confirm`; links, GET filters, and
POST operations retain their native behavior when JavaScript is absent or fails.
There is no SPA router and no client-only page-data fetch.

## Commands

Node is a build and test dependency only. Dependencies and the lockfile are pinned.

```sh
npm ci
npm run check
npm audit
```

Tests are kept outside production sources: pure contract and URL tests live in
`tests/unit`, end-to-end SSR/hydration behavior lives in `tests/integration`, and
shared typed requests live in `tests/fixtures`. `npm run check` runs the complete
suite, then type-checks, builds, and verifies both outputs:

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
The build verifier imports the emitted bundle, checks that React and Node builtins
were not left external, and performs a render smoke test.

The checked-in Vite server bundle is compiled into a WASI Preview 2 component;
Rust embeds that component and the hash-addressed client assets. At runtime the
host supplies those same-origin paths through `RenderRequest.host.assets` and
invokes the component with a fresh, resource-limited Wasmtime store. Host-owned
locale, CSP nonce, and executable asset paths stay outside the page model and
cannot be selected by route data.
Display timestamps are already formatted in the page model so server and browser
rendering never diverge because of timezone or locale differences. User-controlled
values are escaped by React, and the hydration JSON additionally escapes HTML
delimiter characters.

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
link and form action must be a safe same-origin route path, while script and CSS
assets must also be rooted, fragment-free paths with the expected file type.
Adding a route means adding a discriminated `PageModel` variant, its validator,
and complete rendering in `App`; unknown variants fail rather than falling back
to an empty client shell.
