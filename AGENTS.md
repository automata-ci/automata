# Repository instructions

Automata is a greenfield Rust 2024 CI system with an embedded React interface.
Make the current design correct and simple; do not preserve superseded designs.

## Start here

- Read `docs/architecture.md`, the affected crate's `README.md`, and nearby code
  before changing a boundary. Use `docs/development.md` for detailed test and
  service setup.
- For UI work, also read `ui/README.md`, `ui/src/ARCHITECTURE.md`, and
  `ui/src/styles/README.md`.
- Treat `.ci/workflows/ci.yml` as the source of truth for required CI checks and
  `docs/compatibility.md` as the source of truth for GitHub Actions support.

## Engineering rules

- This is greenfield software. Replace an obsolete API, representation, or path
  directly. Do not add compatibility shims, legacy aliases, dual read/write
  paths, deprecated fallbacks, or feature flags that retain superseded behavior.
- Delete replaced and dead code, tests, fixtures, configuration, documentation,
  and dependencies in the same change. Do not comment code out or suppress a
  dead-code warning to keep it around.
- Fix the root cause at the owning layer. Do not use a workaround, special case,
  silent fallback, weakened validation, or test-only branch to make a symptom
  pass. If the proper fix needs an architectural change, make that change.
- Keep each change focused, but leave every touched area internally complete.
  Search for and update all callers, tests, examples, generated inputs, and docs.
- Follow established best practices for the language and library versions pinned
  by this repository. Prefer standard, typed, maintainable designs over clever
  abstractions. Add a dependency only when the existing stack cannot express the
  requirement; justify it and include lockfile and licensing effects.
- First-party Rust stays safe: every crate forbids `unsafe`. Preserve strict
  TypeScript checks; do not bypass them with `any`, unchecked assertions, or
  looser duplicate types.
- Validate untrusted input at its boundary with explicit size and shape limits.
  Fail closed on unknown workflow syntax, protocol variants, capabilities, and
  security state. Never log or fixture real credentials or secret values.
- Do not hand-edit generated files. Use the owning generation workflow and review
  both source and generated diffs. Applied PostgreSQL migrations are immutable
  history: never edit, rename, or remove one; append the next migration and update
  its frozen inventory.

## Architecture

- Keep provider syntax in its frontend/compiler. Scheduling and runners consume
  provider-neutral logical plans and `JobIR`; they do not parse GitHub workflow
  YAML or evaluate GitHub expressions.
- PostgreSQL owns mutable state and coordination. S3-compatible storage owns
  immutable payloads and is never a lock or queue. Coordinate replicas with
  transactions, idempotency, leases, and fencing rather than process-local state.
- Keep domain contracts and ports independent from adapters. Remote boundaries
  use explicit, versioned, bounded protocols; generated transport DTOs do not
  become domain models.
- Preserve trust-domain separation among human sessions, runner mTLS, provider
  credentials, workload credentials, and secrets. Authentication, authorization,
  and durable mutations remain server-owned.
- Rust owns HTTP routing, authorization, data loading, status codes, and
  mutations. React renders typed models; Node.js is never a production server.
- Follow the UI dependency direction:
  `page -> hook/service + presenter -> view -> shared component`. Keep views and
  render functions pure. Use effects only to synchronize with an external system.
  Native links and forms must still work without browser JavaScript.
- Keep CSS in the existing cascade layers and focused modules. Consume semantic
  tokens instead of raw repeated values, avoid specificity escalation and
  `!important`, and preserve semantic HTML, keyboard operation, visible focus,
  reduced motion, forced colors, and responsive layouts.

## Tests and evidence

- Tests are part of the implementation. Every behavior change needs focused unit
  coverage and, when a public or cross-component boundary changes, an integration
  or contract test. A bug fix includes a regression test that fails without it.
- Test observable contracts, exact typed errors, state transitions, side effects,
  and failure non-effects. Do not assert private implementation shape, debug
  strings, source text, or only `is_ok()`/`is_err()` when a stronger contract is
  available.
- Keep tests deterministic. Coordinate concurrency with barriers, notifications,
  or Tokio's paused clock; do not use sleeps as assertions. External-service tests
  remain explicit opt-in lanes with documented prerequisites.
- Never weaken, delete, ignore, or broaden a test merely to make a change pass.
  Update it only when the intended observable contract changed.
- State exactly which checks ran. Never claim success from an unrun check, and do
  not treat parsing, compilation, or a component test as end-to-end evidence.

## Build, run, and verify

Run commands from the repository root unless a command changes directory. The
pinned Rust toolchain installs through rustup. UI work requires Node.js 24.19.0
and npm. Keep scratch data inside the ignored tree:

```sh
export TMPDIR="$PWD/target/task-tmp/local"
install -d -m 0700 -- "$TMPDIR"
```

Build the complete workspace and run a focused Rust test while iterating:

```sh
cargo build --workspace --locked
cargo test -p automata-ci-core --locked
```

Replace the package and add a test-name filter for the code you changed.

Verify the public command surface and its focused integration tests:

```sh
cargo run --locked --bin automata -- --help
cargo test --locked -p automata-ci --test cli
```

For frontend hot reload:

```sh
cd ui
npm ci
npm run dev
```

Stop the development server or use another terminal for the full frontend gate:

```sh
cd ui
npm run check
npm audit --audit-level=low
```

`automata server` and `automata-runner run` require PostgreSQL, object storage,
Results, mTLS, provider, and sandbox configuration. Follow
`crates/automata-ci/README.md` and
`crates/automata-ci-runner/config/README.md`; do not add a mock fallback to avoid
those dependencies.

Run the narrowest relevant checks first. Before review, Rust changes normally
require the workspace baseline:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
```

Also run the affected script, PostgreSQL, renderer, distribution, or platform
lane described in `docs/development.md`. If a prerequisite is unavailable,
report the omitted command and reason.

## Documentation and handoff

- Update the owning documentation with a behavior or command change. Follow
  `docs/documentation-style.md`: lead with the useful fact, distinguish working
  behavior from plans, and support capability claims with the strongest test
  evidence available.
- Keep one owner for each fact and link to it instead of copying long procedures.
- Review the final diff for unrelated edits, dead paths, stale names, leaked
  secrets, hand-edited generated output, and claims unsupported by tests.
