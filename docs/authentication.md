# Authentication, authorization, publication, and secrets

Automata currently supports GitHub as its human identity provider. When the
complete human-auth configuration is present, `automata server` composes GitHub
browser and device login, browser and CLI sessions, request authentication,
RBAC, the RBAC management JSON API, and repository publication settings. Human
authentication is opt-in; a partial configuration fails startup.

Automata is still bootstrap software. Repository publication and RBAC
administration have authenticated browser surfaces backed by the same durable
authorization boundaries as the management JSON API. Repository-secret
management has authenticated HTTP routes, built-in-provider activation, a
cryptographic-erasure cleanup worker, a value-free authenticated repository UI,
and a repository-scoped operator CLI. The browser UI supports capability-gated
create, replace, delete, and built-in-provider activation. There is no
operational CLI replacement command, runner delivery, or external-provider
support.

## Current capability map

| Capability | Current status |
| --- | --- |
| GitHub browser login | Composed with single-use state, S256 PKCE, encrypted durable transactions, and a browser-only session cookie |
| GitHub device login | Composed through the HTTP API and operational in `automata auth login` |
| CLI session lifecycle | `automata auth login`, `auth status`, and `auth logout` are operational on Linux with an available Secret Service |
| Installation setup | An anonymous, Armed-only native `/setup` page and one-use web/device routes are composed for a configured bootstrap proof and exact numeric GitHub user ID; no dedicated setup CLI is provided |
| Request authentication | Browser cookies are accepted only on browser routes; CLI bearers are accepted only on `/api/v1/` routes; runner mTLS remains a separate machine domain |
| RBAC | Explicit roles, permissions, current direct bindings, and current numeric GitHub organization/team mappings are resolved at request time |
| RBAC administration | Authenticated browser pages and JSON routes manage members, roles, role permissions, and direct tenant/repository/runner-group bindings; no dedicated RBAC CLI is provided |
| Repository publication | The browser settings page independently configures dashboard, log, and artifact audiences as private, authenticated, or public |
| Secret providers | The provider-neutral SPI requires either Automata envelope encryption or verified provider-managed encryption for every durable value copy |
| Repository secret management | Authenticated repository-scoped HTTP routes compose metadata reads, create/replace, delete, and built-in-provider activation when human authentication and secret-key configuration are complete |
| Repository secret browser UI | Authenticated repository pages expose value-free metadata and only the create, replace, delete, or built-in-provider activation forms authorized for the current session |
| Repository secret CLI | On Linux with a stored CLI session, `secret list`, `secret create`, `secret delete`, `secret provider status`, and `secret provider activate` operate on the built-in provider; replacement is deliberately unavailable |
| Built-in secret provider | The PostgreSQL adapter envelope-encrypts immutable values and composes reserve, stage, confirm, activation, and fenced cryptographic-erasure cleanup |
| Managed-secret delivery | Not composed; jobs do not currently receive managed secret values |
| Configured GitHub provider runtime | The exact provider registry composes signed webhook ingress, public/private source delivery, fenced Check Runs, scoped App service credentials, and lease-bound repository authority for already-materialized Standard jobs; CredentialFree jobs receive none, and generic provider revocation handling remains outside this route |

## Enable GitHub human authentication

The server requires this complete base set:

- `--external-url` — a canonical HTTPS root origin, or a literal-loopback HTTP
  origin together with `--auth-allow-loopback-http` for development;
- `--github-client-id` and `--github-client-secret-source`;
- `--auth-session-hash-key-source`, resolving to exactly 32 bytes; and
- `--auth-encryption-key-source`, plus the non-secret `--auth-key-id` and any
  old `--auth-decryption-key` entries retained during rotation.

Secret options take `env:NAME` or `file:/absolute/path` references, never raw
values. The authentication wrapping key stays outside PostgreSQL and its
backups. Login transactions and GitHub user tokens are authenticated and
envelope-encrypted before persistence; Automata stores only keyed digests of
its own opaque session bearers.

A database with no configured installation additionally requires all four
bootstrap options:

- `--bootstrap-token-source`;
- `--bootstrap-github-user-id` with the exact stable numeric GitHub user ID;
- `--bootstrap-tenant-id`; and
- `--bootstrap-tenant-display-name`.

The tuple arms a one-hour, one-use installation challenge. While the durable
state is exactly Armed, anonymous `GET /setup` exposes one native form that
submits the bootstrap token to `/setup/auth/github`; the token is never part of
the rendered page model. The GitHub authorization returns through the same
configured `/auth/github/callback` as ordinary sign-in, and the server selects
SignIn versus InstallationSetup only from the transaction's durable HMAC-bound
purpose. Beginning setup moves the state to LoginBound and withdraws the page;
successful completion configures the installation, issues the first browser
session, and makes the authenticated Access pages usable in the same running
process. Only the configured GitHub identity can complete the challenge.

Once installation is configured, replicas read the durable installation
identity and the bootstrap tuple may be removed. A partial tuple, a different
identity, or enabling authentication on an unconfigured installation without
the tuple fails closed. One-use device setup routes also exist, but there is no
dedicated setup CLI.

See the [`automata` configuration reference](../crates/automata-ci/README.md#human-authentication)
and [control-plane setup](deployment.md#optional-github-human-authentication)
for the deployment boundary.

## Browser and CLI sign-in

Browser login uses the GitHub App web flow. The server stores an encrypted,
single-use transaction so any replica can finish the callback without making it
replayable. After exchange, Automata fetches the stable GitHub user identity and
issues an Automata browser session. A GitHub access token is never an Automata
session credential.

For the CLI, select the control-plane root origin and run:

```console
automata --server-url https://ci.example.test auth login
automata --server-url https://ci.example.test auth status
automata --server-url https://ci.example.test auth logout
```

The client accepts HTTPS, or literal-IP loopback HTTP for development. It does
not follow redirects or use proxy environment settings. The GitHub verification
URL and user code are written only to the controlling terminal; session material
does not enter command arguments, ordinary stdout/stderr, or JSON output.

The Linux client requires `secret-tool` and an unlocked OS Secret Service. It
stores exactly one credential per canonical server origin, verifies an exact
read-back, rejects ambiguous matches, and has no plaintext credential-file
fallback. This is a provider-managed encryption boundary: the operator must
choose and configure a Secret Service whose backing store is encrypted at rest.
Automata can verify the Secret Service protocol behavior, but it cannot attest
how a desktop keyring implementation protects its own database.

### Crash-safe CLI activation

Completing the GitHub device flow does not immediately create a usable bearer.
The server first commits the CLI session as `pending_activation` with an
activation window of no more than five minutes. Pending sessions cannot resolve,
refresh their idle lifetime, or authenticate an ordinary API request.

The client then writes and verifies the bearer in Secret Service before asking
the server to activate that exact CLI-domain credential. Activation rechecks the
current principal, tenant membership, session audience, and authorization
revision in one transaction. Repeating activation for the same active session is
safe. If the process stops after local custody but before it receives the
activation response, `auth status` retries activation; `auth logout` can still
revoke it if activation committed, or remove local custody while an unusable
pending row reaches its short deadline. If local custody fails, the client
attempts bounded remote revocation and does not report a successful login.

This two-phase boundary prevents a lost device-poll response from leaving a
usable session whose bearer was never durably stored by the client.

### Repository-secret CLI

Repository-secret commands use the same Linux CLI session and Secret Service
custody described above. Log in to the exact control-plane origin first, and
keep `secret-tool` plus the selected unlocked Secret Service available for every
operation. The current scope is one exact GitHub repository in
`repo:OWNER/REPOSITORY` form.

The value-free and mutation commands are:

```console
automata --server-url https://ci.example.test secret provider status
automata --server-url https://ci.example.test secret provider activate
automata --server-url https://ci.example.test secret list --scope repo:OWNER/REPOSITORY
automata --server-url https://ci.example.test secret create DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY \
  --from-file /absolute/path/to/value
automata --server-url https://ci.example.test secret delete DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY
```

`secret list` returns metadata only, and provider inspection is also value-free.
Creation accepts a value only from `--from-file` or redirected standard input;
it never accepts a value as a command argument or JSON field. A `--from-file`
path must be absolute and resolve without symbolic links to a single-link,
owner-owned regular file with mode `0400` or `0600`. To use redirected input
instead, omit `--from-file`:

```console
automata --server-url https://ci.example.test secret create DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY < /path/to/value
```

Interactive value entry is rejected. The input bytes are bounded, kept in
zeroizing custody, and never printed. Deletion asks for an exact confirmation on
the controlling terminal unless `--yes` is supplied. Rerun `secret provider
status` after activation and `secret list` after a create or delete to verify the
sanitized durable state.

The current commands require these permission combinations:

- `secret list`: `secrets:metadata:read`;
- `secret create`: `secrets:metadata:read` and `secrets:create`;
- `secret delete`: `secrets:metadata:read` and `secrets:delete`;
- `secret provider status`: `secret-providers:read`; and
- `secret provider activate`: `secret-providers:read` and
  `secret-providers:manage`.

These combined read-and-mutate requirements are a current operational
limitation, not a least-privilege claim. Missing and forbidden repositories or
secrets remain non-enumerating. The CLI has no replacement command and refuses
`secret create` when the name already exists. The authenticated repository UI
provides value-free metadata plus capability-gated create, replace, delete, and
built-in-provider activation. There is still no managed-secret delivery to jobs
or external-provider support.

## Session and trust-domain separation

- Production browser sessions use `Secure`, `HttpOnly`, `SameSite=Lax`
  host-only cookies. Unsafe browser requests also require the exact configured
  origin and a session-derived CSRF proof. Literal-loopback HTTP uses separate
  development cookie names and cannot reuse production cookies.
- CLI sessions are Automata bearer credentials with the `automata.cli`
  audience. Browser cookies use the separate `automata.web` audience, and the
  middleware rejects either credential on the other's route family.
- Session resolution reloads the current principal, tenant membership, direct
  role bindings, numeric GitHub mapping evidence, and authorization revision.
  Disabled principals, suspended memberships, expired or revoked sessions, and
  stale authorization revisions fail closed.
- Runners authenticate with direct TLS 1.3 mutual TLS and cannot call human
  administration APIs. Static fleet registration is the current enrollment
  path; automated enrollment and issuance remain unavailable.
- GitHub App installation tokens, GitHub user tokens, storage credentials, and
  key-encryption roots are separate from browser, CLI, runner, and workload
  credentials.

## RBAC and management surfaces

Roles have no magic names. A role called `administrator`, a GitHub organization
owner, or an unmapped GitHub team receives no implicit privilege. Permissions
must be explicitly attached to a role, and a current binding or configured
numeric GitHub organization/team mapping must grant that role at the applicable
tenant, repository, or runner-group scope.

The current `/api/v1/` management API exposes user and role collections, exact
user details with bounded role-assignment pages, exact role details with the
complete permission catalog, role permissions, and direct bindings. Reads
require `members:read` or `roles:read`; mutations use `members:manage`,
`roles:manage`, or `role-bindings:manage` as appropriate.
Every mutation reauthenticates the exact actor and current authorization
revision inside the same PostgreSQL transaction, uses optimistic revisions,
preserves the last-manager invariant, and appends a sanitized immutable audit.
Caller-provided role names, tenant IDs, or revisions are never treated as
authority.

The JSON routes require a CLI-audience session, which `automata auth` manages.
The browser Access pages use the separate browser session, origin, and CSRF
boundary to expose the same revision-fenced member, role, permission, and direct
binding operations. Dedicated RBAC CLI commands are not implemented. GitHub
organization/team mapping administration is also not part of either management
surface.

The browser does provide one focused management surface at
`/{owner}/{repository}/settings/access`. Authorized viewers can inspect the
repository publication policy; an independently authorized editor can update it
through a bounded, session-CSRF-protected form.

## Public and private repositories

Each repository selects three audiences independently:

| Setting | Controls | Values |
| --- | --- | --- |
| Dashboard | Repository, workflow, run, and job metadata | private, authenticated, public |
| Logs | Exact admitted job log streams | private, authenticated, public |
| Artifacts | Exact finalized artifact metadata and downloads | private, authenticated, public |

`private` grants no publication access, although an explicit RBAC permission can
still authorize the resource. `authenticated` permits an authenticated member
of the same tenant. `public` permits anonymous, read-only access; publication
never grants a mutation or management permission.

Runs snapshot all three requested audiences and the positive policy revision at
admission. A later repository setting does not reinterpret an already admitted
run. Log and artifact authorization is independent of dashboard visibility, so
a project can publish logs or artifacts without exposing sibling dashboard
metadata, or expose a public dashboard while keeping both outputs private.
Missing and denied direct resources remain non-enumerating.

### Secret-safe output narrowing

Publication settings are an upper bound, not a promise that every output will be
public. When user code can read an Automata-managed secret, dashboard metadata
keeps its requested audience, but logs and artifacts are immutably narrowed to
private. Raw user-controlled stdout and stderr are suppressed before persistent
log ingestion for those attempts; masking is defense in depth, not the
confidentiality boundary. Dynamic masks and stop-command tokens are discovered
across both output channels before either is emitted.

Secretless jobs and jobs that receive only a narrow brokered capability may use
the configured public log/artifact audience. Automata cannot identify arbitrary
sensitive data a workflow obtains outside its managed secret boundary, so
workflow authors must still avoid writing unrelated credentials or private data
to output and artifacts.

## Encrypted-at-rest secret providers

Every secret-provider adapter must declare exactly one closed durable protection
mode:

- `automata_envelope`: Automata authenticates and envelope-encrypts the value
  before durable storage; or
- `provider_managed_encryption`: the adapter verifies that the external
  provider encrypts every durable value copy within its own storage boundary.

There is no plaintext, unknown, or unspecified mode. Provider errors, audit
records, metadata reads, and debug output must not contain values or opaque
provider handles. Temporary plaintext remains an in-memory execution concern
and must not be written to swap, crash dumps, diagnostics, or durable staging by
an adapter.

The built-in PostgreSQL adapter uses the Automata envelope mode. It stores only
authenticated ciphertext, a nonce, a wrapped data key, and bounded non-secret
metadata. The envelope context binds the exact tenant and immutable version
identity. The active wrapping key and decrypt-only rotation keys remain outside
PostgreSQL; database files, WAL, replicas, snapshots, backups, and the host
volume holding root keys still require their own encryption and access controls.

Secret creation and replacement use a value-free durable mutation ledger:
reservation binds the exact descriptor, expected revision/predecessor, actor,
and deterministic provider request; the provider then writes only an encrypted,
non-resolvable staged version; confirmation atomically promotes the exact winner,
advances the logical head, supersedes the predecessor when applicable, and
records a sanitized receipt and audit. Exact retries reuse the same durable
bytes. The ledger covers tenant, repository, and environment descriptor shapes,
while the currently exposed management repository remains repository-scoped.

With a complete secret-key configuration, `automata server` composes the
built-in adapter and runs its fenced cryptographic-erasure cleanup worker. Each
tenant's durable built-in provider is initially seeded unconfigured; activation
is an explicit, revision-guarded management operation. When human authentication
is also configured, the server exposes authenticated, repository-scoped HTTP
routes for metadata reads, create/replace, delete, provider inspection, and
built-in-provider activation. The operator CLI exposes only the current subset
documented above; replacement remains browser-only. Runner delivery and external
providers remain unavailable, so jobs currently receive no managed secret
values.

The built-in path is fail-closed at restart, periodic readiness, and every write
boundary. Immutable authenticated canaries prove loaded bytes for the active
and every durably required wrapping key; absent or mismatched material blocks
provider, API, cleanup, and stale-recovery writes. Cleanup and recovery use
bounded operation deadlines and monotonic fences, provider state and revision
have a reauthorization-bound read for lost-response recovery, and closed
metrics expose pending, in-progress, and dead-letter cleanup state without
identifiers. These guarantees do not compose runner secret delivery,
replacement in the CLI, or external providers.

Repository SCM credentials use a separate workload broker. The GitHub adapter
creates a short-lived installation token for exactly one provider repository ID
and the minimum requested permission map only after a Standard job's durable
manifest, materialization, lease, runner session, fencing token, and `JobIR`
identity revalidate. Runner control can then attach that exact repository
authority to the lease offer. CredentialFree jobs bypass every issuer and
receive an empty authority bundle. The mandatory autonomous worker separately
supervises logical preparation, activation, and materialization after admission;
composing that worker and this credential boundary does not by itself establish
end-to-end runner, provider, or service-image acceptance. A workload credential
is neither a human session nor a general-purpose runner credential.

Primary GitHub references are [generating a GitHub App user access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app),
[refreshing user access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens),
[generating an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token),
and [GitHub App security practices](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app).
