# Security policy

Automata 0.1 is bootstrap software and is not supported for production use.
No public release exists yet. Security fixes currently target the latest
reviewed source on `main`; after publication, the project will state which
release lines receive fixes.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability or include secrets,
tokens, private workflow contents, or exploit details in a public discussion.

Use GitHub's private vulnerability reporting form:

<https://github.com/automata-ci/automata/security/advisories/new>

Include the affected version or commit, deployment shape, impact, reproduction
steps, and any suggested mitigation. Use placeholder credentials and the
smallest safe proof of concept. Reports are handled on a best-effort basis
while the project is in bootstrap development; the maintainer will coordinate
disclosure and attribution with the reporter before publishing an advisory.

For ordinary correctness, compatibility, or hardening suggestions that do not
need an embargo, use the public issue templates instead.

## Security boundary

The current support and isolation claims are documented in
[Compatibility](docs/compatibility.md) and [Architecture](docs/architecture.md).
A successful build, workflow
parse, or runner diagnostic is not a production-safety claim.
