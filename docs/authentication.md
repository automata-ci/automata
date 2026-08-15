# Authentication, authorization, publication, and secrets

GitHub is the implemented human identity provider. When its complete
configuration is present, `automata server` enables browser and device login,
browser and CLI sessions, tenant RBAC, management APIs, and repository access
settings. Authentication is optional, but a partial configuration stops the
server at startup.

Managed-secret administration and exact-version delivery are implemented for
the built-in PostgreSQL provider. Eligible leased jobs receive values only over
the direct mTLS runner listener; external and dynamically leased providers and
variable-value delivery remain unsupported.

## Capability map

| Capability | Status | Limit |
| --- | --- | --- |
| Browser login | Available when configured | GitHub App web flow; browser routes accept browser sessions only. |
| CLI login | Available on Linux | Requires `secret-tool` and an unlocked Secret Service. |
| Initial installation | Available when armed | Anonymous `/setup` is one-use and restricted to one configured numeric GitHub user ID. |
| RBAC | Available when authentication is configured | Roles, permissions, direct bindings, and numeric GitHub organization/team mappings resolve on every request. |
| RBAC management | Available in browser and JSON API | There are no dedicated RBAC CLI commands. Organization/team mapping management is not exposed. |
| Repository visibility | Available in browser | Dashboard, logs, and artifacts have separate audiences. |
| Repository secret management | Available in browser, JSON API, and a bounded CLI | The CLI cannot replace a value; the browser can. |
| Protected-environment review | Available through the bounded CLI | Requires `environments:approve` plus a current reviewer assignment for the exact repository and environment revision. |
| Workflow reruns | Available through the bounded CLI | Requires `runs:rerun`; only exact completed-run selections within the current retention and attempt limits are admitted. |
| Built-in secret provider | Component complete | Values are envelope-encrypted in PostgreSQL; wrapping keys remain outside the database. |
| External secret providers | Planned | No external adapter is available. |
| Secret delivery to jobs | Experimental | Eligible Standard jobs can receive exact pinned versions from the built-in provider over an mTLS-only ephemeral exchange. Durable lease state remains value-free, and the runner masks every value before acknowledgement. External/dynamic providers and variable-value delivery are unsupported. |
| GitHub workload credentials | Experimental | Standard jobs may receive lease-bound repository authority; CredentialFree jobs receive none. |

## Enable GitHub human authentication

Configure all of these options together:

- `--external-url`: the canonical HTTPS origin. Literal loopback HTTP also
  requires `--auth-allow-loopback-http` and is for development only.
- `--github-client-id` and `--github-client-secret-source`.
- `--auth-session-hash-key-source`, resolving to exactly 32 bytes.
- `--auth-encryption-key-source` and `--auth-key-id`.
- One `--auth-decryption-key` for each older key still needed during rotation.

Secret sources use `env:NAME` or `file:/absolute/path`; the command line never
accepts the secret value itself. Authentication wrapping keys must be stored
outside PostgreSQL and its backups.

An installation with no administrator also needs:

- `--bootstrap-token-source`;
- `--bootstrap-github-user-id`, containing the stable numeric GitHub user ID;
- `--bootstrap-tenant-id`; and
- `--bootstrap-tenant-display-name`.

This tuple arms a one-hour, one-use setup challenge. While it is armed,
anonymous `GET /setup` shows the native setup form. Starting the flow withdraws
that form. Only the configured GitHub identity can finish setup. Completion
creates the installation, issues the first browser session, and enables the
authenticated access pages without restarting the server.

Remove the bootstrap tuple after all replicas can read the configured
installation. A missing field, a different identity, or an unconfigured
installation without the tuple fails closed.

The full option reference is in the
[`automata` README](../crates/automata-ci/README.md#human-authentication).

## Browser and CLI sign-in

Browser login stores a single-use encrypted transaction so any replica can
finish the GitHub callback. Automata then loads the stable GitHub user identity
and issues its own browser session. A GitHub token is never accepted as an
Automata session.

For CLI access:

```console
automata auth --server-url https://ci.example.test login
automata auth --server-url https://ci.example.test status
automata auth --server-url https://ci.example.test logout
```

The client accepts HTTPS and literal loopback HTTP. It does not follow redirects
or use proxy environment variables. The verification URL and device code are
written to the controlling terminal, not ordinary stdout, stderr, or JSON.

On Linux, the client stores one credential per canonical server origin in the
OS Secret Service and verifies it by reading it back. It rejects ambiguous
matches and has no plaintext-file fallback. Automata verifies the Secret
Service protocol; the operator is responsible for choosing an implementation
whose database is encrypted at rest.

### Crash-safe CLI activation

The device flow first creates a `pending_activation` session with a lifetime of
at most five minutes. That session cannot authenticate API requests. The client
stores and verifies the bearer in Secret Service, then activates the exact
credential on the server.

`auth status` retries activation if the client stopped after storing the bearer
but before receiving the activation response. `auth logout` revokes an active
session or removes local custody while an unusable pending session expires. A
local storage failure triggers a bounded revocation attempt and is never
reported as a successful login.

## Rerun a completed workflow from the CLI

The authenticated `automata rerun` command accepts a bounded
`OWNER/REPOSITORY` coordinate and an exact source-run UUID plus one of
`entire-workflow`, `failed-jobs-and-dependents`, or `job-and-dependents`. The
last selection also requires an exact `--job-id`.

```console
automata rerun --server-url https://ci.example.test \
  automata-ci/automata \
  20000000-0000-4000-8000-000000000002 \
  --selection entire-workflow --output json
```

The client loads the server-scoped CLI session from Secret Service, applies a
bounded retry policy, and uses one operation UUID throughout. Successful output
includes that UUID. If the final result is indeterminate, retry the exact same
request with the error's `--operation-id` value. See
[workflow reruns](workflow-reruns.md) for selection and retention constraints.

## Review a protected environment from the CLI

The authenticated `automata environment-review` command records one exact
approval or rejection for a repository UUID and gated job-attempt UUID:

```console
automata environment-review --server-url https://ci.example.test \
  aaaaaaaa-1111-4111-8111-111111111111 \
  22222222-2222-4222-8222-222222222222 \
  --decision approve --output json
```

Use `--decision reject` to reject the request. Both UUIDs must use non-nil,
lowercase, hyphenated canonical form. The client loads only the server-scoped
Secret Service session and returns the current closed gate state: `waiting`,
`resolving`, `ready`, `rejected`, `expired`, or `cancelled`.

The command sends a mutation only once. If transport fails or the server cannot
return a trustworthy result, the outcome may be indeterminate because the
decision or subsequent credential resolution could already be durable. An exact
same-decision replay by the same reviewer is idempotent only when that decision
was durably applied. Retry only the same repository UUID, attempt UUID, and
decision; a different decision conflicts. A review of an expired or cancelled
gate conflicts on every retry, even when terminalizing the gated attempt is a
durable side effect of that request.

## Manage repository secrets from the CLI

Log in to the same server origin first. Repository scope uses
`repo:OWNER/REPOSITORY`.

```console
automata secret --server-url https://ci.example.test provider status
automata secret --server-url https://ci.example.test provider activate
automata secret --server-url https://ci.example.test list --scope repo:OWNER/REPOSITORY
automata secret --server-url https://ci.example.test create DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY \
  --from-file /absolute/path/to/value
automata secret --server-url https://ci.example.test delete DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY
```

`list` and `provider status` return metadata only. `create` reads a value from
`--from-file` or redirected standard input; it never accepts one in an argument
or JSON field. A value file must be absolute, have no symbolic links, be owned
by the caller, have one hard link, and use mode `0400` or `0600`.

To use redirected input:

```console
automata secret --server-url https://ci.example.test create DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY < /path/to/value
```

Interactive input is rejected. Delete asks for exact terminal confirmation
unless `--yes` is present. Verify a mutation with `provider status` or `list`.

Permissions are:

| Command | Required permissions |
| --- | --- |
| `secret list` | `secrets:metadata:read` |
| `secret create` | `secrets:metadata:read`, `secrets:create` |
| `secret delete` | `secrets:metadata:read`, `secrets:delete` |
| `secret provider status` | `secret-providers:read` |
| `secret provider activate` | `secret-providers:read`, `secret-providers:manage` |

The read-and-mutate combinations are an operating limitation, not a
least-privilege claim. The CLI refuses to create an existing name and has no
replace command. The browser supports authorized replacement. Neither path
delivers values to jobs.

## Session and trust domains

- Production browser sessions use secure, HTTP-only, same-site host cookies.
  Unsafe requests also require the configured origin and a session-derived CSRF
  proof. Loopback development uses different cookie names.
- CLI sessions have the `automata.cli` audience. Browser sessions have
  `automata.web`. Each route family rejects the other credential.
- Every request reloads the principal, membership, bindings, GitHub mapping
  evidence, and authorization revision. Disabled, suspended, expired, revoked,
  or stale sessions fail closed.
- Runners authenticate with mTLS and cannot call human administration APIs.
- GitHub user and installation tokens, storage credentials, key roots, runner
  identities, workload tokens, browser sessions, and CLI sessions are separate
  credentials.

## RBAC and management surfaces

Role names have no built-in meaning. A role named `administrator`, a GitHub
organization owner, or an unmapped GitHub team receives no implicit access.
Permissions must be attached to a role, and a current binding or numeric GitHub
mapping must grant it at tenant, repository, or runner-group scope.

The `/api/v1/` API manages users, roles, role permissions, and direct bindings.
Reads require `members:read` or `roles:read`; writes require the matching
`members:manage`, `roles:manage`, or `role-bindings:manage` permission. Writes
reauthenticate the actor in the same PostgreSQL transaction, compare revisions,
preserve the last manager, and append a value-free audit record.

The JSON API requires a CLI session. Browser access pages expose the same
revision-fenced operations through browser sessions, origin checks, and CSRF
proofs. Repository visibility is managed at
`/{owner}/{repository}/settings/access`.

## Repository visibility

Each repository sets three independent audiences:

| Setting | Content | Values |
| --- | --- | --- |
| Dashboard | Repository, workflow, run, and job metadata | private, authenticated, public |
| Logs | Admitted job log streams | private, authenticated, public |
| Artifacts | Finalized artifact metadata and downloads | private, authenticated, public |

`private` grants no publication access, although RBAC may still authorize the
resource. `authenticated` allows a signed-in member of the same tenant.
`public` allows anonymous read-only access and never grants a mutation.

A run snapshots the three audiences and policy revision at admission. Later
settings do not reinterpret that run. Denied or missing direct resources return
non-enumerating responses.

### Output narrowing when a job can read secrets

Publication is an upper limit. If user code can read an Automata-managed
secret, the run keeps its requested dashboard audience but logs and artifacts
become private. The runner redacts exact registered credential values before
persistence. Secret-derived job outputs persist a marker; unrelated public
outputs keep their value.

Redaction cannot detect a transformed or split value, so it is not used as the
confidentiality boundary. Authors must also avoid printing sensitive data
obtained outside Automata's managed-secret boundary.

## Secret storage

Every secret adapter declares one protection mode:

- `automata_envelope`: Automata encrypts and authenticates the value before
  durable storage.
- `provider_managed_encryption`: the adapter verifies that its provider
  encrypts every durable copy.

There is no plaintext or unspecified mode. Errors, audits, metadata, and debug
output may not contain values or opaque provider handles.

The PostgreSQL adapter stores authenticated ciphertext, a nonce, a wrapped data
key, and bounded metadata. The envelope binds tenant and immutable version
identity. Active and decrypt-only wrapping keys stay outside the database;
database files, WAL, replicas, backups, and the key host still need their own
access controls and storage encryption.

Secret mutation uses a value-free ledger. It reserves a descriptor and expected
revision, stages an encrypted non-resolvable version, and confirms the winning
version in one transaction. Retries reuse the same stored bytes. Deletion and
stale-intent recovery use fenced cleanup and cryptographic erasure.

The server checks authenticated canaries for every required wrapping key at
startup, during readiness, and before writes. Missing or wrong key material
blocks provider, API, recovery, and cleanup writes. Metrics expose aggregate
cleanup states without identifiers.

Repository source credentials use a separate broker. For a materialized
Standard job, the GitHub adapter can mint a short-lived installation token for
one provider repository and a minimum permission map after revalidating the
lease, runner session, fence, and JobIR identity. CredentialFree jobs bypass the
issuer. Managed-secret delivery is independent: an eligible Standard job's
durable lease carries only a value-free, exact-version binding overlay. The
runner fetches built-in-provider values through the direct mTLS ephemeral route,
keeps them in zeroizing execution-local custody, registers every value with the
output masker, and acknowledges only after complete custody. This boundary does
not establish end-to-end workflow compatibility; external/dynamic providers and
variable-value delivery remain unsupported.
