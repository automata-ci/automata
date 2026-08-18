# Documentation style

Write for someone who is deciding whether to use Automata, trying it for the
first time, operating it under pressure, or changing the code. Give that reader
the fact or action they need before implementation detail.

Describe Automata as working software. Do not put a project-wide development
status disclaimer in front of the first useful fact. Qualify only the specific
feature, provider, interface, or distribution channel that has a real limit.

## Choose the page type

Keep one main purpose per page:

- A tutorial gets a new reader to a working result.
- A how-to guide solves a specific operational problem.
- A reference page records exact commands, fields, states, and limits.
- An explanation page describes design and trade-offs.

A page may link to another type. It should not turn a short procedure into an
architecture essay or make a reference table carry a tutorial.

## State capability precisely

Use these labels when a status needs to be explicit:

| Label | Meaning |
| --- | --- |
| Available | Reachable through the documented product path and covered by the stated tests. |
| Component complete | Implemented and tested at its boundary, but not yet proven in the full composition. |
| Experimental | Reachable, but its interface or operating requirements may still change. |
| Planned | Accepted design or roadmap work that is not implemented. |
| Unsupported | Rejected, ignored only where the contract says so, or not implemented. |
| Published | An exact version is visible in the named public registry. |

Most pages do not need status labels. Use them in compatibility tables and
roadmaps where the distinction changes a user's decision. A supported subset is
`Available` when the documented path works and rejects behavior outside that
subset; incomplete parity does not make the whole path experimental.

Do not turn parsing, a unit test, a migration, or an internal API into a product
claim. Prefer evidence in this order:

1. a documented command against the complete composition;
2. an end-to-end or acceptance test;
3. a boundary or component test;
4. implementation and schema inspection;
5. a plan or design document.

Name the weaker evidence when it is all that exists. Planned package names,
release workflows, and deployment manifests do not prove publication or
availability.

## Organize around the reader

When relevant, answer these questions in order:

1. What will this page help me do?
2. Does it work now, and what are the limits?
3. What do I need before starting?
4. What is the shortest safe procedure?
5. How do I verify the result?
6. How do I recover from likely failures?
7. What should I read next?

Put prerequisites beside the first step that needs them. Explain credentials,
network exposure, privilege, and destructive effects before the command that
introduces them.

## Write like a maintainer

- Lead with a fact, outcome, or action.
- Use plain verbs and concrete nouns.
- Keep paragraphs focused on one idea.
- Prefer a short example over a second abstract explanation.
- Say who owns an action or decision. Avoid vague phrases such as “it is
  recommended” or “some users may find.”
- Remove scene-setting, recaps, and claims that a fact is important when the
  consequence already shows why it matters.
- Avoid promotional adjectives and canned contrasts such as “not just X, but
  Y.”
- Delete presentation phrases such as “this section explores,” “it is worth
  noting,” “in conclusion,” “paves the way,” and “marks a milestone.”
- Do not use ornamental words such as “delve,” “showcase,” “pivotal,”
  “multifaceted,” or “invaluable” where a concrete verb or noun will do.
- Do not manufacture rhythm with repeated groups of three, bold lead-ins on
  every bullet, or an intro-list-summary pattern on every page.
- Do not force ideas into groups of three or give every section the same
  rhythm.
- Use “currently” only with a dated or verifiable state. Replace it with the
  actual limit where possible.
- Keep contract words such as `exact`, `bounded`, and `durable` where they name
  a real invariant. Remove them when they merely add emphasis.

There is no punctuation ban and no automated “AI detector” gate. Review for
specific writing habits: inflated significance, vague attribution, repetitive
qualifiers, unnecessary summaries, fake quotations, and prose that describes
the document instead of the software.

## Write procedures that can be trusted

- Present one supported path before alternatives.
- Make command blocks copyable.
- Use placeholders that cannot be mistaken for real credentials or domains.
- Follow a state-changing command with an observable verification step.
- Give expected output only when it is stable and useful for diagnosis.
- State the supported platform and required permissions.
- Put rollback or cleanup beside risky operations.
- Never make an unpublished installer, crate, image, or URL look available.

## Keep one owner for each fact

Overview pages summarize and link. The component or operator guide owns exact
configuration, limits, and recovery steps. The compatibility page owns support
claims. The implementation plan owns unfinished acceptance gates. The release
guide owns publication procedure.

When a capability changes, update the owning page first, then search for short
summaries elsewhere. Avoid copying large status blocks between the root README,
architecture, compatibility, and implementation plan.

## Use product names consistently

- `Automata` is the project.
- `automata` and `automata-runner` are commands.
- `automata-ci` and `automata-ci-runner` are workspace package names and the
  intended crates.io names. Call them published only when the registry contains
  the exact version.
- Workspace packages use `automata-ci-*`; Rust crate identifiers use
  `automata_ci_*`.
- `automata-ci-service-proxy` is an internal helper image, not a product image.
- A GitHub Actions workflow contains runs, jobs, attempts, and steps; do not use
  those runtime terms interchangeably.

Package READMEs rendered outside GitHub should use absolute links back to this
repository. Other repository documentation should use relative links.

## Review checklist

Before merging a documentation change, check that:

- every availability claim matches code, tests, and public registries;
- planned work is visibly separate from working behavior;
- copied commands use real flags and have a verification step;
- security boundaries and failure behavior are stated before operational
  detail;
- links and anchors resolve;
- repeated status text has one authoritative owner;
- the page can be skimmed without reading introductory filler;
- the prose does not show the habits listed above.
