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

For a copyable local server walkthrough, use
[control-plane setup](https://github.com/automata-ci/automata/blob/main/docs/deployment.md).
This page is the configuration reference.

## Server listeners

Each server replica binds three mandatory sockets and, when configured, one
private metrics socket before it starts:

| Option | Default | Traffic |
| --- | --- | --- |
| `--listen` | `127.0.0.1:8080` | Human API, health, readiness, GitHub webhook, and SSR |
| `--results-listen` | `127.0.0.1:8081` | GitHub Actions Results-compatible requests |
| `--runner-listen` | `127.0.0.1:9090` | Direct mutual-TLS runner protocol over HTTP/2 |
| `--metrics-listen` | disabled | Loopback-only Prometheus/OpenMetrics endpoint |

The runner listener must validate client certificates directly. Do not pass a
runner identity through reverse-proxy headers. A proxy-terminated runner
transport would require a separate adapter and trust contract.

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
2. binds the three mandatory listeners and the optional metrics listener;
3. connects to PostgreSQL and applies embedded migrations;
4. applies the configured static runner fleet;
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

Database connections force full TLS certificate and hostname verification.
Local development may select `--database-transport loopback-plaintext`, but
the effective target must be a Unix socket or literal loopback IP address;
hostnames and remote addresses are rejected.

Required server sources are:

| Option | Default reference |
| --- | --- |
| `--database-url-source` | `env:AUTOMATA_DATABASE_URL` |
| `--s3-access-key-source` | `env:AUTOMATA_S3_ACCESS_KEY` |
| `--s3-secret-key-source` | `env:AUTOMATA_S3_SECRET_KEY` |
| `--results-signing-key-source` | `env:AUTOMATA_RESULTS_SIGNING_KEY` |
| `--control-plane-encryption-key-source` | `env:AUTOMATA_CONTROL_PLANE_ENCRYPTION_KEY` |
| `--runner-client-ca-source` | `env:AUTOMATA_RUNNER_CLIENT_CA_PEM` |
| `--runner-server-cert-source` | `env:AUTOMATA_RUNNER_SERVER_CERT_PEM` |
| `--runner-server-key-source` | `env:AUTOMATA_RUNNER_SERVER_KEY_PEM` |

The runner trust bundle must contain at least one PEM certificate. The server
identity must contain a PEM certificate chain and exactly one supported private
key. Runner transport requires TLS 1.3 and direct client-certificate validation.

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

Migration `0013_encrypted_runner_payloads.sql` refuses to run while either
obsolete pre-release plaintext retry table contains rows. Those databases are
not supported upgrade sources for v0.1; recreate the current schema or restore
a reviewed backup that already uses it. The migration never deletes those
ledgers and must not be bypassed. See the deployment guide for the schema and
rotation boundary.

## Object storage

The server and every runner in an installation use the same bucket and logical
key prefix. The server publishes immutable workflow, JobIR, log, result, and
artifact objects; runners verify those exact keys and publish immutable action
bundles. A differing prefix fails closed as a missing object and is never
searched or guessed.

For local RustFS, explicitly allow a literal loopback HTTP endpoint:

```console
automata server \
  --s3-endpoint http://127.0.0.1:9000/ \
  --s3-allow-loopback-http \
  --s3-bucket automata-dev \
  --s3-prefix automata/v1 \
  # ...required secret, Results, and runner TLS references...
```

Plain HTTP object-store endpoints anywhere other than literal loopback are
rejected even when the development option is present.

## Results, artifacts, and cache

The dedicated Results listener serves the implemented artifact protocol used
by `actions/upload-artifact` v7.0.1 and CacheService v2 used by `actions/cache`
5.0.5. Eligible jobs receive short-lived authority bound to their run, job,
attempt, and fence; no runner-wide Results credential exists.

Cache lookup checks the current ref first and then the server-owned default
branch read-only. Entries expire after seven inactive days and a repository has
a 10 GiB LRU quota. Artifact deletion, cache management, physical object
collection, and BuildKit cache compatibility are not implemented. See the
[`automata-ci-results-github` reference](../automata-ci-results-github/README.md)
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
production TLS substitute. Follow the
[runner-host guide](https://github.com/automata-ci/automata/blob/main/docs/platforms/arch-linux.md)
before applying the firewall policy.

## Workflow admission and autonomous progress

The server exposes no local bearer workflow ingress. Configure the exact GitHub
provider registry below to admit supported signed `push` webhooks for
`.github/workflows/ci.yml` on `refs/heads/main`.

Admission validates and persists immutable workflow evidence asynchronously.
Its durable receipt does not mean a job has finished: the mandatory autonomous
worker subsequently supervises logical preparation, activation, and
materialization. End-to-end runner, provider, and service-image acceptance
remains a separate gate.

## Static runner bootstrap

The server has no automated runner enrollment API yet. Operators can supply
one absolute, privileged fleet document with
`--static-runner-registration-file`; it is applied after migrations and before
readiness, and exact replay is idempotent. Use the repository's
[static runner walkthrough](https://github.com/automata-ci/automata/blob/main/docs/deployment.md#bootstrap-one-static-local-runner)
to derive canonical capabilities, issue a client-only certificate, and satisfy
the root-owned file and coordinated-rotation rules.

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

On Linux, the operational device client is:

```console
automata auth --server-url https://ci.example.test login
automata auth --server-url https://ci.example.test status
automata auth --server-url https://ci.example.test logout
```

It requires `secret-tool` and an unlocked OS Secret Service. There is no
plaintext credential-file fallback. A completed device flow first creates an
unusable server-side `pending_activation` session for no more than five minutes;
the client stores and verifies the credential before activating it. Status can
retry an indeterminate activation. The operator is responsible for selecting a
Secret Service with encrypted backing storage because Automata cannot attest
the external keyring implementation. Complete GitHub provider configuration
adds the exact signed webhook, public/private source-delivery, fenced Check
Runs, scoped App-credential runtime, and exact lease-bound repository authority
for an already-materialized Standard GitHub job. CredentialFree jobs receive
no runtime authority, and there is no fallback/default installation route.
The mandatory autonomous worker supervises asynchronous logical preparation,
activation, and materialization after admission; a successful receipt alone
does not mean a runnable job has completed the end-to-end acceptance path.

## GitHub provider registry

Enable the provider runtime with one owner-only manifest reference, never an
inline JSON value:

```console
--github-provider-config-source file:/etc/automata/github-provider.json
```

Add that option to the complete `automata server` command; it is not a
standalone command.

Start from the checked
[`github-provider.example.json`](config/github-provider.example.json). The
outer file and each nested `private_key_source` or `hmac_secret_source` must be
an `env:NAME` or absolute `file:/path` reference accepted by the secret-source
policy; secret bytes do not belong in the manifest. File sources must be
owner-only regular files and cannot be symlinks.

Each repository entry binds one existing tenant to stable numeric GitHub App
installation, repository, and owner IDs, an exact `owner/name`, its canonical
`default_branch` name, and a unique non-nil connection UUID. The default branch
is server-owned cache metadata and is never taken from a job or action request.
Revisions are positive and non-regressing. The entry's
`policy_revision` must equal every nested authority revision, and authority
UUIDs are globally unique. A `public` repository must set
`private_repository_source_read` to `null`; a `private` repository must provide
that exact authority. `checks_write` is mandatory for both. Use
`credential_free` only for jobs intentionally barred from credential-bearing
authority; `standard` selects the credential-bearing, fail-private output
profile. Unknown fields, aliases, duplicate identities, incoherent visibility,
and partial authority shapes fail startup.

Every repository `tenant_id` must equal the server's one effective UI tenant.
With human authentication enabled, that is the tenant in durable installation
state (or its configured bootstrap tenant while setup is active); without human
authentication, it is the validated fallback tenant, which defaults to `local`.
Set it with `--fallback-tenant-id` (or `AUTOMATA_FALLBACK_TENANT_ID`) when the
default is not appropriate. A mismatch fails startup before the App private key
or webhook HMAC is loaded and before provider manifests or runtime state are
constructed. The current registry has no tenant chooser or multi-tenant
compatibility mode.

The GitHub App webhook URL is the public Automata origin plus
`/webhooks/github`. Configure GitHub with the same HMAC secret referenced by the
manifest, subscribe it to `push` events, and grant `checks:write` for every
entry plus `contents:read` only for Private source. The current manifest and
delivery contract admit only `.github/workflows/ci.yml` on
`refs/heads/main` for the `push` event; another workflow, ref, or event is
rejected rather than silently generalized. Rotations advance the relevant
configuration, verifier, manifest, policy, and authority revisions rather than
reusing an old identity with changed bytes.

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

The Linux operator CLI exposes a repository-scoped subset when its CLI session
is stored in an unlocked Secret Service and `secret-tool` remains available:

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
and refuses create when the name already exists. Runner delivery and external
providers remain unsupported, so jobs do not receive managed secret values.

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
