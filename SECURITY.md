# Security policy

Report suspected Automata vulnerabilities through GitHub's private
vulnerability reporting form. Security fixes target the latest source on
`main`; this page will list supported release lines when versioned public
releases are available.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Do not include
secrets, tokens, private workflow contents, personal data, or exploit details
in a public discussion, fixture, log, or screenshot.

Submit the report at:

<https://github.com/automata-ci/automata/security/advisories/new>

Include:

- the affected version or commit;
- the deployment shape and execution provider;
- the expected and observed security boundary;
- reproduction steps and impact; and
- a suggested mitigation, if you have one.

Use placeholder credentials and the smallest safe proof of concept. The
maintainer will acknowledge the report, investigate it, and coordinate the fix,
disclosure timing, and attribution with the reporter. Do not publish details
before that coordination is complete.

For correctness, compatibility, or hardening suggestions that do not require an
embargo, use the public issue templates.

## Security boundaries

Automata separates human sessions, tenant authorization, runner mTLS identity,
provider credentials, workload credentials, managed secrets, and workload OIDC
tokens. Jobs do not receive the runner's host-container socket or control-plane
credentials. Unsupported syntax and unproved capabilities fail closed.

The exact supported workflow and provider boundaries are documented in
[Compatibility](docs/compatibility.md). The component and trust-domain design
is documented in [Architecture](docs/architecture.md), and runner identity
lifecycle is documented in [Runner control-plane security and
enrollment](docs/runner-control-plane-security-and-enrollment.md).

A successful build, workflow parse, or host diagnostic does not by itself prove
safe job execution. Use the deployment and runner guides, keep credentials out
of command arguments, and do not bypass failed admission checks.
