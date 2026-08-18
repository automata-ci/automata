# `automata` control plane

The `automata-ci` workspace package builds the `automata` command. It is both
the control-plane service and the administration CLI. No crates.io release is
published yet; build the reviewed source checkout with:

```console
cargo run --locked -p automata-ci -- --version
```

For source builds and other installation options, use the repository
[getting-started guide](https://github.com/automata-ci/automata/blob/main/docs/getting-started.md).
The bootstrap build exposes two service modes:

- `automata preview` serves health endpoints and the embedded SSR interface
  without external dependencies.
- `automata server` starts the complete current composition and fails unless
  PostgreSQL, S3-compatible storage, Results configuration, and runner mTLS
  identity are valid.

This page is the configuration reference for the complete server.

## Server listeners

Each server replica binds three mandatory sockets and, when configured,
private management and metrics sockets before it starts:

| Option | Default | Traffic |
| --- | --- | --- |
| `--listen` | `127.0.0.1:8080` | Human API, health, readiness, GitHub webhook, and SSR |
| `--results-listen` | `127.0.0.1:8081` | GitHub Actions Results-compatible requests |
| `--runner-listen` | `127.0.0.1:9090` | Direct mutual-TLS runner protocol over HTTP/2 |
| `--management-listen` | disabled | Private mutual-TLS shard-management gRPC |
| `--metrics-listen` | disabled | Loopback-only Prometheus/OpenMetrics endpoint |

The runner listener must validate client certificates directly. Do not pass a
runner identity through reverse-proxy headers. A proxy-terminated runner
transport would require a separate adapter and trust contract.

The management listener is opt-in and is not needed by a standalone
self-hosted installation. Enabling it requires one stable authority ID, shard
ID, exact delegated-actor HTTPS issuer, dedicated client CA, server identity,
and one or more SHA-256 pins for allowed leaf client certificates. mTLS first
validates the client chain; the leaf pin then maps that verified connection to
the configured provisioning authority. Supply both old and new pins during a
bounded certificate-rotation overlap. This listener connects the public
workspace-provisioning gRPC contract directly to the same PostgreSQL database
used by the other replicas in the shard, reusing this replica's existing pool.

The management authority also enables a versioned delegated-actor HTTP surface
on the human listener. A hosted control plane signs a short-lived ES256 actor
assertion; Core verifies the configured issuer and audience, resolves current
workspace membership and RBAC from PostgreSQL, and performs every read through
the same authorization-enforcing data boundary as self-hosted SSR. Version 2
provides:

| Method | Path | Result |
| --- | --- | --- |
 | `GET` | `/internal/v2/workspaces/{workspace_id}/viewer` | Current Core principal and authorization revision |
 | `GET` | `/internal/v2/workspaces/{workspace_id}/repositories` | Authorized repository directory |
 | `GET` | `/internal/v2/workspaces/{workspace_id}/repositories/{owner}/{repository}/runs` | Filtered workflow and run page |
 | `GET` | `/internal/v2/workspaces/{workspace_id}/repositories/{owner}/{repository}/runs/{run_id}` | Run, job, and artifact snapshot |
 | `GET` | `/internal/v2/workspaces/{workspace_id}/repositories/{owner}/{repository}/runs/{run_id}/jobs/{job_id}` | Job metadata and structured-stream availability |
 | `POST` | `/internal/v2/workspaces/{workspace_id}/repositories/{owner}/{repository}/runs/{run_id}/jobs/{job_id}/live-ticket` | One-time, origin-bound direct log capability |
 | `POST` | `/internal/v2/workspaces/{workspace_id}/repositories/{repository_id}/workflows/{workflow_id}/dispatches` | Authorized, idempotent workflow dispatch with Core-owned source resolution |

Responses are `no-store` JSON and carry `protocol_version: 2` plus the exact
workspace ID. Opaque pagination cursors must be returned unchanged. Run
numbers and artifact IDs and sizes are decimal strings
so JavaScript clients cannot silently lose integer precision. Missing and
unauthorized repository resources remain indistinguishable as `404`; a valid
assertion does not move authorization policy into the hosted layer.

When managed-secret encryption is configured, `--runner-public-url` is also
required. It is the exact HTTPS origin configured as each runner's
`control_endpoint`; the private value route rejects any different HTTP/2
authority. Secret delivery uses the same direct mTLS listener, never the human
listener or a proxy-forwarded identity.

All three mandatory listeners require fixed, nonzero ports. The human/webhook
listener is raw HTTP: keep it on literal loopback, or place a trusted isolating
TLS reverse proxy in front of a non-loopback bind and explicitly assert that
deployment boundary with `--human-trusted-reverse-proxy`. This flag does not
make forwarded identity headers authoritative.

Production Results URLs use HTTPS, normally terminated by a trusted reverse
proxy in front of the dedicated listener. A non-loopback raw HTTP listener is
accepted with an HTTPS public URL only when the deployment explicitly asserts
that isolation with `--results-trusted-reverse-proxy`. Plain HTTP is accepted
only through the explicit development policy and an exact loopback or
private-interface bind.

## Startup and readiness

`automata server`:

1. validates configuration and secret references;
2. binds the three mandatory listeners and optional management and metrics listeners;
3. connects to PostgreSQL and applies embedded migrations;
4. verifies durable runner capabilities against this replica;
5. initializes the immutable S3 adapter;
6. writes and verifies a readiness object; and
7. composes Results, runner control, maintenance, database-time logical-run
   finalization and result projection, the mandatory autonomous preparation,
   activation, and materialization worker, the web application, and the
   configured GitHub provider runtime when present.

`/healthz` reports process and build health. `/readyz` reports database,
object-store, and mandatory autonomous-worker readiness. Load balancers and
orchestration platforms should use `/readyz` for traffic admission.

Database and object-store checks repeat at the configured readiness interval.
A missing credential or dependency never falls back to preview mode.

When tuning maintenance, `--stale-runner-session-timeout-seconds` must be
strictly greater than `--maintenance-interval-seconds`; otherwise startup
rejects the maintenance policy.

## Secret references

Secret and PEM options accept a reference, not the value itself:

```text
env:ENVIRONMENT_VARIABLE
file:/mounted/secret/path
```

On Unix, a `file:` path must be absolute. Every path component is opened without
following symbolic links, and the target must be a regular file owned by the
server's effective user, owner-readable, with no group/other permission bits
(normally mode `0600`). Relative paths, symlinks, special files, loose modes,
and files owned by another user fail closed. Non-Unix file loading is currently
unavailable until an equally strong native path implementation exists. Never
put the value itself after `env:`/`file:` or directly in an option.

This applies to database, object-store, runner TLS, Results signing,
authentication, and wrapping-key credentials. References are redacted from
debug and startup errors, and loaded values have context-specific size limits.

Database URLs use one exact `postgresql://` TCP grammar with an explicit host,
port, user, non-empty password, and database. Query parameters, fragments,
socket paths, the `postgres://` alias, `.pgpass`, and every ambient `PG*`
environment setting are rejected. Connections use the fixed `public` search
path.

The default `--database-transport web-pki-verify-full` requires TLS certificate
and hostname verification through SQLx's compiled Web PKI roots. The explicit
`web-pki-plus-private-ca-verify-full` mode adds one bounded canonical CA from
`--database-private-ca-source`; SQLx retains the Web PKI roots in that mode, so
it is intentionally a trust union rather than private-CA-only trust. Local
development may select `loopback-plaintext`, but only with a literal-loopback
TCP address. Hostnames, remote addresses, and Unix sockets are rejected.
Generated local topology uses a reserved `.invalid` database DNS identity with
the explicit Web-PKI-plus-private-CA union, so no public CA can issue for that
name even though the compiled public roots remain installed.

Required server sources are:

| Option | Default reference |
| --- | --- |
| `--database-url-source` | `env:AUTOMATA_DATABASE_URL` |
| `--s3-access-key-source` | `env:AUTOMATA_S3_ACCESS_KEY` |
| `--s3-secret-key-source` | `env:AUTOMATA_S3_SECRET_KEY` |
| `--results-signing-key-source` | `env:AUTOMATA_RESULTS_SIGNING_KEY` |
| `--control-plane-encryption-key-source` | `env:AUTOMATA_CONTROL_PLANE_ENCRYPTION_KEY` |
| `--runner-client-ca-cert-source` | `env:AUTOMATA_RUNNER_CLIENT_CA_CERT_PEM` |
| `--runner-client-ca-key-source` | `env:AUTOMATA_RUNNER_CLIENT_CA_KEY_PEM` |
| `--runner-server-ca-source` | `env:AUTOMATA_RUNNER_SERVER_CA_PEM` |
| `--runner-server-cert-source` | `env:AUTOMATA_RUNNER_SERVER_CERT_PEM` |
| `--runner-server-key-source` | `env:AUTOMATA_RUNNER_SERVER_KEY_PEM` |

The runner trust bundle must contain at least one PEM certificate. The server
identity must contain a PEM certificate chain and exactly one supported private
key. Runner transport requires TLS 1.3, `TLS_AES_256_GCM_SHA384`, HTTP/2, and
direct client-certificate validation. Runner keys are generated locally by
`automata-runner enroll`; the server stores only each signed leaf digest.

The mandatory control-plane encryption source must resolve to exactly 32 random
bytes. It protects durable runner command/RPC payloads and GitHub App
server-service credential envelopes; the separate human-authentication key
protects human GitHub OAuth access and refresh tokens only.
`--control-plane-encryption-key-id` names the active wrapping key;
repeat `--control-plane-decryption-key "KEY_ID=env:NAME"` or
`--control-plane-decryption-key "KEY_ID=file:/absolute/path"` for old
decrypt-only keys during rotation.
New runner-command, RPC-response, and GitHub App service-credential envelopes
use only the active key. Retain each old key until no durable envelope of any
of those kinds, or retained backup, can refer to it. Root wrapping keys must be
stored outside PostgreSQL; protect their mounted host volume, and encrypt
PostgreSQL data, WAL, replicas, snapshots, and backups at rest as separate
controls.

Only a fresh database initialized by the canonical
`0001_initial_schema.sql` is supported. Never copy, relabel, or reinterpret
plaintext `runner_command_outbox` or `runner_rpc_receipts` retry rows as
current encrypted state. Recreate the database or restore a reviewed backup
produced by the current encrypted schema.

## Object storage

The server and every runner in an installation use the same bucket and logical
key prefix. The server publishes immutable workflow, JobIR, log, result, and
artifact objects; runners verify those exact keys and publish immutable action
bundles. A differing prefix fails closed as a missing object and is never
searched or guessed.

HTTPS object storage has one explicit trust mode. The default
`--s3-tls-trust web-pki` uses the platform Web PKI roots. To trust a private
service, select `--s3-tls-trust private-ca` and provide exactly one bounded CA
certificate through `--s3-private-ca-source env:NAME` or
`--s3-private-ca-source file:/absolute/path`. Private-CA mode starts from an
empty root store, never adds Web PKI roots, and never retries under a different
trust policy. The source is subject to the same secure-file and redaction rules
as other privileged inputs and is capped at 1 MiB. It must be one canonical
RFC 7468 certificate with 64-column Base64, LF line endings, one terminal LF,
no preamble/trailing bytes, and `keyCertSign` whenever KeyUsage is present.

For example, an HTTPS S3-compatible service with its own CA uses:

```console
automata server \
  --s3-endpoint https://objects.internal.example/ \
  --s3-tls-trust private-ca \
  --s3-private-ca-source file:/run/secrets/object-store-ca.pem \
  --s3-bucket automata
```

For local RustFS, explicitly allow a literal loopback HTTP endpoint:

```console
automata server \
  --s3-endpoint http://127.0.0.1:9000/ \
  --s3-allow-loopback-http \
  --s3-bucket automata-dev \
  --s3-prefix automata/v1 \
  --s3-kms-key-id default \
  # ...required secret, Results, and runner TLS references...
```

Plain HTTP object-store endpoints anywhere other than literal loopback are
rejected. `--s3-allow-loopback-http` is also rejected for an HTTPS endpoint or
with private-CA trust, so it cannot remain as an inert or ambiguous setting.
After argument validation, connection security is exactly one closed state:
Web PKI HTTPS, exact-private-CA HTTPS, or literal-loopback plaintext.

Object writes use provider-managed AES-256 (`SSE-S3`) by default. Set
`--s3-kms-key-id` to select `SSE-KMS` with one exact non-secret key identity;
reads then fail closed unless the object store reports both `aws:kms` and that
same identity. The pinned local RustFS service exposes its configured local
master key as `default`, so the development command selects that identity.

## Results, artifacts, and cache

The dedicated Results listener serves the implemented artifact protocol used
by `actions/upload-artifact` v7.0.1 and CacheService v2 used by `actions/cache`
5.0.5. Eligible jobs receive short-lived authority bound to their run, job,
attempt, and fence; no runner-wide Results credential exists.

Cache lookup checks the current ref first and then the server-owned default
branch read-only. Entries expire after seven inactive days and a repository has
a 10 GiB LRU quota. Artifact deletion, cache management, and physical object
collection are not implemented. The bounded Buildx/BuildKit session and
provenance surface is implemented, but cache interoperability is not yet
production-proven and live CacheService v2 acceptance remains open. See the
[`automata-ci-runner-results` reference](../automata-ci-runner-results/README.md)
for the tested protocol slices.

## Results development mode

A job sandbox cannot reach a host-loopback Results listener. Local end-to-end
work therefore uses one exact private host bind, one asserted job-facing host,
and the dedicated firewall policy:

```console
export AUTOMATA_LOCAL_SECRET_DIR="$(pwd -P)/target/local-secrets"
automata server \
  --results-listen 192.168.0.8:8081 \
  --results-public-url http://host.containers.internal:8081/ \
  --results-allow-development-http \
  --results-trusted-private-host host.containers.internal \
  --results-signing-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/results-hmac.key" \
  # ...remaining required configuration...
```

This mode is for a firewall-constrained development bridge. It is not a
production TLS substitute. The operator must install and verify an independent
host firewall policy before enabling the listener.

## Workflow admission and autonomous progress

The server exposes no local bearer workflow ingress. Configure the exact GitHub
provider registry below to admit supported signed GitHub webhook deliveries.
For an admitted revision, `all_direct` workflow discovery selects every direct
lowercase `.yml` or `.yaml` file under `.ci/workflows/`; nested paths, other
extensions, and unauthenticated revisions are rejected.

Admission validates and persists immutable workflow evidence asynchronously.
Its durable receipt does not mean a job has finished: the mandatory autonomous
worker subsequently supervises logical preparation, activation, and
materialization. End-to-end runner, provider, and service-image acceptance
remains a separate gate.

## Runner enrollment

After CLI login, `automata runner token` creates a one-use tenant/group-scoped
token with a 15-minute default lifetime. `automata-runner enroll` consumes it,
generates the private key locally, registers the exact configured capability
ceiling, and creates new TLS credential files without overwriting. The server
stores a domain-separated token digest, the signed leaf digest, and the exact
non-secret redemption response needed for idempotent recovery; it never stores
token plaintext or runner private keys. See the
[runner security and lifecycle plan](../../docs/runner-control-plane-security-and-enrollment.md).

## Human authentication

Human authentication is opt-in and atomic. When its complete configuration is
present, the server composes GitHub browser login and device-flow HTTP
endpoints, envelope-encrypted login/provider state, hashed browser/CLI session
credentials, cookie/origin/CSRF enforcement, fresh numeric membership
authority, and the RBAC management HTTP API. At minimum it requires `--external-url`,
`--github-client-id`, `--github-client-secret-source`,
`--auth-session-hash-key-source`, and `--auth-encryption-key-source`. A new
installation also requires the complete one-use `--bootstrap-token-source`,
`--bootstrap-github-user-id`, `--bootstrap-tenant-id`, and
`--bootstrap-tenant-display-name` tuple; replicas reject partial tuples.

GitHub is the current human provider. Browser cookies and CLI bearers have
separate audiences: browser credentials are admitted only to browser routes,
while `/api/v1/` accepts only CLI credentials. The current management API
exposes collection and exact-detail reads for members and roles, including
bounded member-assignment pages and each role's complete permission catalog. It
and the browser Access pages handle role permissions and direct
tenant/repository/runner-group bindings. Every mutation uses bounded native
forms and reauthorizes the actor from current durable state; caller-provided
roles and revisions are not authority. Dedicated RBAC CLI commands are not
available.

On Linux and macOS, the operational device client is:

```console
automata auth --server-url https://ci.example.test login
automata auth --server-url https://ci.example.test status
automata auth --server-url https://ci.example.test logout
```

Linux requires `secret-tool` and an unlocked OS Secret Service. macOS uses
Security.framework and requires an unlocked writable default user Keychain;
Keychain access is deliberately noninteractive and fails closed when locked.
There is no plaintext credential-file fallback. A completed device flow first
creates an unusable server-side `pending_activation` session for no more than
five minutes; the client stores and verifies the credential before activating
it. Status can retry an indeterminate activation. On Linux, the operator is
responsible for selecting a Secret Service with encrypted backing storage
because Automata cannot attest the external keyring implementation. Complete GitHub provider configuration
adds the exact signed webhook, public/private source-delivery, bounded periodic
schedule discovery, fenced Check Runs, scoped App-credential runtime, and exact lease-bound repository authority
for an already-materialized Standard GitHub job. CredentialFree jobs receive
no runtime authority, and there is no fallback/default installation route.
The mandatory autonomous worker supervises asynchronous logical preparation,
activation, and materialization after admission; a successful receipt alone
does not mean a runnable job has completed the end-to-end acceptance path.

The same protected CLI session can request a durable workflow rerun:

```console
automata rerun --server-url https://ci.example.test \
  automata-ci/automata \
  20000000-0000-4000-8000-000000000002 \
  --selection entire-workflow
```

The command supports failed-job and exact job closures, keeps one operation ID
across bounded retries, and prints that ID for safe exact replay. See the
[workflow-rerun guide](../../docs/workflow-reruns.md) for the complete contract.

A current protected-environment reviewer can also record one exact decision for
a repository and gated job attempt:

```console
automata environment-review --server-url https://ci.example.test \
  aaaaaaaa-1111-4111-8111-111111111111 \
  22222222-2222-4222-8222-222222222222 \
  --decision approve --output json
```

The command uses the same OS credential-manager-only CLI session custody, accepts
`approve` or `reject`, and returns only the closed gate state. It does not retry
the mutation automatically; an indeterminate result may be retried only with
the exact same repository UUID, attempt UUID, and decision.

## GitHub provider registry

The GitHub provider is database-backed. There is no replica-local provider JSON
file or provider CLI flag. The private mTLS shard-management API applies two
independent, monotonically versioned resources:

- one shard-wide GitHub App configuration containing the dashboard origin,
  App identity and credentials, webhook secret, Check name, runner policy, and
  scheduler policy;
- one complete repository desired set per workspace. Omission from a newer set
  is authoritative, including an empty set used to disconnect a workspace.

App private keys and webhook secrets are envelope-encrypted before their
transaction commits, using the mandatory control-plane key provider. PostgreSQL
stores ciphertext and authenticated envelope metadata, never plaintext.
Management operation IDs are idempotent and revisions must advance. Current
desired state is retained separately from durable operation receipts used to
answer retries. Superseded configuration and repository selections are replaced
rather than accumulated without a current rollback or audit consumer.

At startup, every control-plane replica loads one repeatable-read snapshot,
decrypts the current credentials, validates the runner and repository policy,
and derives stable internal connection and distinct service-authority
identities. Private repositories receive separate source-read and pull-request
files-read authorities; public repositories receive neither. A configured App
with no selected repositories leaves the provider runtime disabled while
remaining ready for repository onboarding. Live revision watching and omitted
repository authority retirement remain follow-up reconciliation work.

The GitHub App webhook URL is the public Automata origin plus
`/webhooks/github`. Configure GitHub with the same HMAC secret referenced by the
configuration, subscribe only to the supported `push`, `pull_request`, `merge_group`,
and `repository_dispatch` events selected for the installation. The App's
registration-wide permissions are Administration read, Checks write, Contents
read, Pull requests read, and Merge queues read; Automata's repository-source
authority remains scoped separately per repository. Administration read is
required to authenticate the repository's effective Actions permission defaults.
A missing permission or provider `403` fails startup, and an expired or invalid
observation keeps later workflow admission fail-closed. Each event must satisfy
its exact configured
source-selection policy; an unconfigured event, source, or revision is rejected
rather than silently generalized. Rotations advance the relevant configuration,
verifier, manifest, policy, and authority revisions rather than reusing an old
identity with changed bytes.

## Repository publication

The authenticated browser settings page at
`/{owner}/{repository}/settings/access` independently selects private,
authenticated, or public audiences for dashboard metadata, logs, and artifacts.
Public access is read-only. Runs snapshot all three choices at admission, and
direct log/artifact reads do not depend on dashboard visibility.

Publication is capped by immutable output-safety evidence. The runner redacts
registered credential values before persisting stdout/stderr. If user code can
read a managed secret, logs and artifacts remain private even when the
repository requests public output. Dashboard metadata keeps its requested
audience. Secretless and capability-only attempts may use configured public
log/artifact publication.

Terminal outputs are classified independently. Explicitly public values are
retained; secret-derived values and values containing registered credentials
persist only a marker.

## Managed-secret status

The provider-neutral SPI requires every adapter to declare either Automata
authenticated envelope encryption or verified provider-managed encryption for
all durable value copies. The built-in PostgreSQL adapter implements the
Automata envelope boundary, and its durable mutation path separates a value-free
reservation, encrypted non-resolvable staging, and exact confirmation.

The optional `--secret-encryption-key-source`,
`--secret-encryption-key-id`, and `--secret-decryption-key` values configure the
rotation-aware local keyring. A complete configuration composes the built-in
provider and its fenced cryptographic-erasure cleanup worker; it does not
activate the provider. Each tenant's durable provider is initially seeded
unconfigured, and activation is an explicit, revision-guarded management
operation. With human authentication configured, the server also exposes
authenticated, repository-scoped HTTP routes for metadata reads,
create/replace, delete, provider inspection, and built-in-provider activation.

The Linux and macOS operator CLI exposes a repository-scoped subset when its
CLI session is stored in the available OS credential manager (`secret-tool`
plus an unlocked Secret Service on Linux, or an unlocked default user Keychain
on macOS):

```console
automata secret --server-url https://ci.example.test provider status
automata secret --server-url https://ci.example.test provider activate
automata secret --server-url https://ci.example.test list --scope repo:OWNER/REPOSITORY
automata secret --server-url https://ci.example.test create DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY --from-file /absolute/path/to/value
automata secret --server-url https://ci.example.test delete DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY
```

Creation accepts values only from a safe, owner-only `--from-file` path or
redirected standard input, never from a command argument or JSON field. The
authenticated repository Secrets page exposes value-free metadata and only the
create, replace, delete, or built-in-provider activation forms authorized for
the current browser session. The current CLI permission combinations are
`secrets:metadata:read` for list;
`secrets:metadata:read` plus `secrets:create` for create;
`secrets:metadata:read` plus `secrets:delete` for delete;
`secret-providers:read` for provider status; and `secret-providers:read` plus
`secret-providers:manage` for activation. The CLI has no replacement command
and refuses create when the name already exists. Exact-version built-in values
are delivered only after a live lease and current policy/grant/approval check,
over the direct mTLS runner listener. The runner keeps them in bounded,
zeroizing execution-local custody, registers every value with output masking,
and only then acknowledges delivery. The bearer and plaintext never enter
`JobIR`, the command outbox, the runner journal/spool, or PostgreSQL plaintext
columns. External and dynamically leased providers remain unsupported.
Variable-value custody is also not implemented; jobs declaring variable
references remain unleaseable at both the scheduler gate and PostgreSQL lease
transition instead of treating durable variable-version selectors as values.

The built-in path now fails closed at restart, periodic readiness, and every
write boundary. Immutable authenticated canaries prove the loaded bytes for the
active and every durably required wrapping key; absent or mismatched material
blocks provider, API, cleanup, and stale-recovery writes. Cleanup and recovery
use bounded deadlines and monotonic fences, provider state has a
reauthorization-bound read for lost-response recovery, and closed metrics expose
pending, in-progress, and dead-letter cleanup state without identifiers. Root
wrapping keys still belong outside PostgreSQL and its backups, and the
surrounding database, WAL, snapshots, backups, swap, crash dumps, and
key-bearing volumes need independent encryption and access controls.

See the repository's
[authentication and authorization guide](https://github.com/automata-ci/automata/blob/main/docs/authentication.md)
for the complete session, RBAC, publication, and provider boundaries.

## Runner directory

The server exposes a fleet overview at `/runners`. By default it requires a
current browser session with `runners:read` authority. Operators can explicitly
publish the presentation-safe directory with `--runner-directory-public` or
`AUTOMATA_RUNNER_DIRECTORY_PUBLIC=true`. Public rows include only runner name,
group, scheduling labels, availability, desired state, capacity, and last
contact time; durable runner/session identities, network metadata, and raw
capabilities never cross the web-data boundary.

## Preview mode

```console
automata preview --listen 127.0.0.1:8080
```

Preview serves build health, readiness, embedded assets, and the React SSR
interface. It never starts workflow admission, runner control, scheduling,
Results, PostgreSQL, or S3 adapters. CI uses it to exercise the fully static
binary inside a `FROM scratch` image.

Run `automata server --help` for the complete option and environment-variable
reference.
