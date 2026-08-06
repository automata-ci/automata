# Authentication and authorization

This document is the security contract Automata is being built to satisfy. It
must not be read as a claim that every control is already active in the
bootstrap server.

| Capability | Current status |
| --- | --- |
| Provider-neutral human, session, RBAC, machine-identity, token-vault, and key-encryption ports | Implemented and externally tested in `automata-auth` |
| Hardened GitHub OAuth/device/membership HTTP transport | Implemented and externally tested in `automata-github`; not yet wired into the server |
| Durable encrypted login transactions, session hashing, and provider-token persistence | Contract only |
| Browser cookies, CSRF/origin enforcement, and verified revocation webhooks | Contract only |
| Runner enrollment and mTLS verification | Contract only |
| Tenant/resource-scoped authorization in HTTP and CLI handlers | Contract only |

The final system must not couple identity to GitHub or treat an SCM credential
as a control-plane session. The implemented crates define independent,
object-safe ports so provider adapters can be replaced without rewriting RBAC
or runner enrollment.

## Required GitHub App provider behavior

GitHub is the first human provider. Browser login uses the GitHub App web flow
with an unpredictable single-use `state` value and S256 PKCE. CLI login uses
the device flow by default, respects GitHub's polling interval and `slow_down`
responses, and expires locally even if GitHub is unavailable. Browser/device
transactions are encrypted durable records so any control-plane replica can
finish them and a callback cannot be replayed.

After exchange, the server re-fetches the stable GitHub user ID. A GitHub user
access token is never accepted as an Automata bearer token. Automata issues a
separate audience-bound, short-lived session and stores only a hash of its
bearer material. GitHub access/refresh tokens are non-serializable secret types
stored through an authenticated-encryption vault with compare-and-swap token
rotation. The app uses expiring user tokens: GitHub documents an eight-hour
access-token lifetime, a six-month refresh-token lifetime, and rotation of
both values when a refresh token is used.

Authorization is explicit. Configured GitHub organization and team mappings
produce Automata roles, and an RBAC policy maps roles to named permissions. An
organization owner, an unmapped team, or a role literally named
`administrator` receives no implicit privilege. Installation access controls,
repository permissions, protected environments, and runner-group access are
enforced as resource policy in addition to RBAC.

The provider must process GitHub's unavoidable `github_app_authorization`
revocation webhook by invalidating provider credentials and related sessions.
Webhook signatures are verified before decoding or dispatch.

## Required trust-domain separation

- Browser cookies are `Secure`, `HttpOnly`, and `SameSite=Lax`; mutations also
  require CSRF tokens and origin checks.
- CLI sessions are scoped Automata tokens stored with owner-only permissions
  (and a platform credential manager when available). Secret values are read
  from a hidden prompt, stdin, or a file—never command arguments.
- Runners authenticate using short-lived enrollment followed by mTLS machine
  identity. A runner certificate cannot call human administration APIs.
- Workloads receive per-attempt credentials for artifacts, cache, OIDC, and
  SCM operations only after a fenced lease is accepted.
- GitHub App installation tokens, user tokens, orchestrator storage keys, and
  broker credentials never enter a job environment or sandbox mount.

Primary GitHub references are [generating a GitHub App user access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app),
[refreshing user access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens),
and [GitHub App security practices](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app).
