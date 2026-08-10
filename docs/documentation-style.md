# Documentation style

Automata documentation is written for the person trying to decide, install,
operate, or change the project—not for the implementation itself.

## Reader journey

Every user-facing page should answer these questions in order when they apply:

1. What is this page or product for?
2. Is the feature available now, and what are its limits?
3. What do I need before I start?
4. What is the shortest safe path to a useful result?
5. How do I verify that result?
6. Where do I go next or troubleshoot a failure?

Architecture and rationale belong after the usable path, or in a linked design
document.

## Writing rules

- Lead with a concrete outcome in plain language.
- Distinguish implemented behavior, active integration, and future design.
- Use one canonical setup path before listing alternatives.
- Put prerequisites immediately before the commands that need them.
- Make command blocks copyable and include a verification step.
- Explain destructive, privileged, network-exposed, or credential-bearing
  commands before showing them.
- Prefer short sections and descriptive link text over a large table of
  contents.
- Use relative links for repository documentation and verify them after moves.
  Package READMEs rendered outside the repository use absolute GitHub links.
- Keep reference detail near the owning component; link to it from overview
  pages instead of duplicating it.
- Never describe parsing or accepting a workflow as compatibility. Compatibility
  requires the evidence defined in the compatibility contract.

Use `Automata`, `automata`, and `automata-runner` consistently: the first is the
project, and the latter two are executable names. The public crates.io packages
are `automata-ci` and `automata-ci-runner`; internal Cargo packages use
`automata-ci-*`, with the corresponding Rust crate identifiers written as
`automata_ci_*`. Never present a package name as the command a user should run.

Use “GitHub Actions workflow” for source YAML and “run,” “job,” “attempt,” and
“step” for their distinct runtime concepts.

Installation pages must state whether a distribution surface is published,
name its supported platform, verify the installed identity, and provide the
source fallback. Release documentation must distinguish “automation is ready”
from “a release exists”; a copyable command must not imply an unpublished
artifact is currently downloadable.

## README references

The public README structure draws on recurring patterns from mature developer
tools and self-hosted systems:

- [Dagger](https://github.com/dagger/dagger) leads with the user outcome and
  explains its value through a few memorable product qualities.
- [uv](https://github.com/astral-sh/uv) moves cleanly from a one-line definition
  to highlights, installation, and concrete examples.
- [LocalStack](https://github.com/localstack/localstack) pairs installation with
  a quick start and visible verification output.
- [K3s](https://github.com/k3s-io/k3s) clearly names its audience, packaging
  model, tradeoffs, and common points of confusion.
- [`just`](https://github.com/casey/just) demonstrates the core interaction
  before expanding into its full feature reference.
- [`act`](https://github.com/nektos/act) explains both why someone would use the
  tool and how the execution model works.
- [Woodpecker](https://github.com/woodpecker-ci/woodpecker) and
  [Grafana](https://github.com/grafana/grafana) keep the repository README as a
  concise gateway to focused documentation.
- [GitHub Actions Runner](https://github.com/actions/runner) defines the product
  boundary in one sentence and sends setup readers directly to the supported
  guide.
- [Actions Runner Controller](https://github.com/actions/actions-runner-controller)
  uses prerequisite-driven setup and ends with an explicit verification step.
- [ripgrep](https://github.com/BurntSushi/ripgrep) states defaults, platforms,
  scope, and nearby alternatives in its opening paragraph.

These projects are references for information hierarchy and reader experience.
Automata's wording, claims, security constraints, and commands remain grounded
in this repository.
