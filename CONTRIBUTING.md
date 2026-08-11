# Contributing

Automata accepts focused bug fixes, compatibility fixtures, tests,
documentation, and design feedback. For larger work, agree on the scope before
implementation; the project is still working toward its first end-to-end gate.

Participation in project spaces is governed by the
[code of conduct](CODE_OF_CONDUCT.md). Report suspected vulnerabilities through
the private channel in [SECURITY.md](SECURITY.md), not a public issue or pull
request. Never publish credentials, private workflow content, personal data, or
exploit details in fixtures, logs, screenshots, or discussions.

## Choose a contribution

Search the [issue tracker](https://github.com/automata-ci/automata/issues) and
review the [implementation plan](docs/implementation-plan.md) before starting.
If an issue already covers the work, comment there so contributors can
coordinate.

Open an issue before implementing any of the following:

- a new feature or user-visible behavior;
- a broad refactor or a new dependency;
- a public API, protocol, storage schema, or compatibility change; or
- a change to authentication, credentials, isolation, execution, or another
  trust boundary.

Small, self-contained bug fixes, tests, and documentation corrections may be
submitted directly. A pull request can still be declined when the behavior is
outside the current scope, so raise uncertainty early.

Use the repository's issue templates for a
[bug](https://github.com/automata-ci/automata/issues/new?template=bug.yml),
[feature request](https://github.com/automata-ci/automata/issues/new?template=feature.yml),
or
[GitHub Actions compatibility
gap](https://github.com/automata-ci/automata/issues/new?template=compatibility.yml).
A useful report includes the exact Automata version or commit, a minimal
reproduction, expected and actual behavior, and sanitized diagnostics.

## Set up the repository

Install Git and [rustup](https://rustup.rs/), fork the repository, and clone your
fork:

```console
git clone https://github.com/YOUR-USER/automata.git
cd automata
git remote add upstream https://github.com/automata-ci/automata.git
export TMPDIR="$PWD/target/task-tmp/local"
install -d -m 0700 -- "$TMPDIR"
cargo build --workspace --locked
```

The repository selects the Rust version and components through
`rust-toolchain.toml`. Frontend work additionally requires the Node.js version
documented in the [development guide](docs/development.md). That guide also
covers local PostgreSQL and object-storage tests, distribution builds, and the
repository map.

Create a focused branch from an up-to-date `main` branch. Keep generated and
temporary data under the ignored `target/` tree.

## Make the change

- Match the surrounding design and keep the pull request limited to one logical
  outcome. Avoid unrelated formatting, renaming, or dependency updates.
- Preserve the safe-Rust boundary; first-party crates forbid `unsafe` code.
- Add tests at the owning crate's public boundary. A bug fix should normally
  include a regression test that fails without the fix.
- Reject unknown or unsupported workflow behavior explicitly. Do not describe
  parsing or acceptance alone as GitHub Actions compatibility.
- Keep secrets out of process arguments, committed configuration, test
  fixtures, snapshots, logs, and screenshots. Use synthetic placeholders.
- Update user-facing documentation when commands, configuration, status, or
  behavior changes. Follow the [documentation style guide](docs/documentation-style.md).
- Use the owning generation workflow instead of hand-editing generated files.
  Protocol changes follow the
  [protobuf code-generation guide](crates/automata-ci-protocol-protobuf/CODEGEN.md),
  and renderer changes follow the [UI guide](ui/README.md).
- Explain why a new dependency is necessary. Commit the corresponding lockfile
  changes and account for its license and supply-chain impact.

Compatibility claims require the differential evidence defined by the
[compatibility contract](docs/compatibility.md). Changes that cross component or
trust boundaries should remain consistent with the
[architecture](docs/architecture.md).

## AI-assisted work

You are responsible for every submitted change, including work produced with
an AI tool.

- Review and understand every change before submitting it. You must be able to
  explain the behavior, design choices, edge cases, and tests in your own words.
- Apply the same correctness, security, compatibility, testing, documentation,
  licensing, and provenance standards as for any other contribution. Model
  output is not evidence for a compatibility or security claim.
- If an AI tool materially contributed to the code, tests, documentation, or
  design, complete the **AI assistance** section of the pull-request template.
  Name the tool and briefly describe what it helped with. Routine completion,
  spelling, and grammar assistance do not need disclosure.
- Ensure issue descriptions, pull-request descriptions, and review replies
  accurately express your own understanding and judgment. Do not paste raw
  model transcripts in place of an explanation.
- Do not provide secrets, private repository content, personal data, embargoed
  vulnerability details, or other material you are not authorized to share to
  an AI service.
- Verify generated citations, APIs, licenses, test results, and claims against
  primary sources or the repository. Never claim that a check was run when it
  was not.

Do not submit unreviewed generated changes, fabricated reports, or bulk output
that leaves the verification work to maintainers. Disclosure itself does not
count against a contribution.

## Verify the change

Run the narrowest relevant tests while iterating. For example:

```console
cargo test -p automata-ci-core --locked
```

Before requesting review for a Rust change, run the workspace baseline used by
CI:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
```

Frontend changes also require:

```console
cd ui
npm ci
npm run check
npm audit --audit-level=low
```

Run the relevant repository script tests for shell, workflow, installer,
distribution, or renderer changes. The
[CI workflow](.github/workflows/ci.yml) is the source of truth for required
checks; the [development guide](docs/development.md) documents checks that need
PostgreSQL, object storage, Podman, or additional build tools.

Record the exact checks and results in the pull request. If a relevant check was
not run, say so and explain which prerequisite or environment was unavailable.

## Submit a pull request

Open the pull request against `main` and complete the template:

- describe the user-visible or operator-visible outcome and why it is needed;
- link the issue when one exists;
- identify effects on credentials, isolation, storage, protocols, releases, or
  GitHub Actions compatibility;
- list verification performed and any relevant checks not run; and
- disclose material AI assistance as described above.

Use a concise, imperative commit subject and keep the branch free of unrelated
changes. Draft pull requests are welcome when early feedback would help, but
mark the pull request ready only after you have reviewed the complete diff.

Maintainers may request design changes, additional tests, or a smaller scope.
Keep discussion focused on technical evidence and push follow-up commits to the
same branch. All required CI checks must pass before merge, but passing CI does
not guarantee acceptance.

By submitting a contribution, you agree that it may be distributed under the
repository's [MIT License](LICENSE).
