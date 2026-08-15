# Control-plane setup

This guide starts `automata server`, PostgreSQL, RustFS, and three dynamically
enrolled runner processes on an Arch Linux development machine. GitHub login is
required for runner enrollment; repository provider ingress and the built-in
secret provider remain optional.

> [!CAUTION]
> This is not a production deployment. Automated certificate rotation,
> production retention, and the end-to-end compatibility gate are still open.

## What you will run

| Component | Default local address | Purpose |
| --- | --- | --- |
| Human HTTP and SSR | `127.0.0.1:8080` | Health, readiness, UI, authentication, and administration |
| Results API | Exact firewall-constrained RFC 1918 address on port `8081` | GitHub Actions Results-compatible requests from rootless jobs |
| Runner control | `127.0.0.1:9090` | Direct HTTP/2 with mandatory mutual TLS |
| PostgreSQL | `127.0.0.1:5432` | Durable coordination and metadata |
| RustFS S3 API | `127.0.0.1:9000` | Immutable blobs |
| RustFS console | `127.0.0.1:9001` | Local object-store administration |

You need Git, rustup, OpenSSL, rootless Podman, `podman-compose`, `jq`,
`secret-tool`, and an unlocked Secret Service with encrypted backing storage.
The operator is responsible for the external keyring's at-rest protection. The
repository checkout supplies the Compose definition, local tests, and example
configuration used below.

## 1. Install Automata and clone the repository

Follow [Getting started](getting-started.md#install-both-commands) to install both
commands from a reviewed source checkout. No public release or crates.io
package is available yet. Verify the commands before starting durable services:

```console
automata --version
automata-runner --version
```

Clone the matching source revision if you did not install from an existing
checkout:

```console
git clone https://github.com/automata-ci/automata.git
cd automata
```

## 2. Start PostgreSQL and RustFS

```console
podman-compose --file deploy/dev/compose.yaml up --detach
podman-compose --file deploy/dev/compose.yaml ps
```

Initialize and verify the local S3 bucket with the repository's contract test:

```console
export AUTOMATA_TEST_S3_ENDPOINT='http://127.0.0.1:9000/'
export AUTOMATA_TEST_S3_BUCKET='automata-dev'
export AUTOMATA_TEST_S3_ACCESS_KEY='automata-local'
export AUTOMATA_TEST_S3_SECRET_KEY='automata-local-secret-change-me'
export AUTOMATA_TEST_S3_KMS_KEY_ID='default'
cargo test -p automata-ci-blob-s3 --test blob_s3 --all-features --locked -- rustfs_contract:: --ignored
```

## 3. Create local-only credentials

Keep development credentials under the ignored `target/` tree:

```console
export AUTOMATA_LOCAL_SECRET_DIR="$(pwd -P)/target/local-secrets"
umask 077
install -d -m 0700 -- "$AUTOMATA_LOCAL_SECRET_DIR"
printf '%s\n' 'postgresql://automata:automata-local-only@127.0.0.1:5432/automata?sslmode=disable' > "$AUTOMATA_LOCAL_SECRET_DIR/database-url"
printf '%s\n' 'automata-local' > "$AUTOMATA_LOCAL_SECRET_DIR/s3-access-key"
printf '%s\n' 'automata-local-secret-change-me' > "$AUTOMATA_LOCAL_SECRET_DIR/s3-secret-key"
openssl rand 32 > "$AUTOMATA_LOCAL_SECRET_DIR/results-hmac.key"
openssl rand 32 > "$AUTOMATA_LOCAL_SECRET_DIR/control-plane-wrapping.key"
chmod 0600 "$AUTOMATA_LOCAL_SECRET_DIR"/*
```

Create a short-lived local certificate authority and a server certificate. The
CA is also the trust root for experimental runner client certificates:

```console
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 30 \
  -subj '/CN=Automata local development CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca-key.pem" \
  -out "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca.pem"

openssl req -newkey rsa:3072 -nodes -sha256 \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$AUTOMATA_LOCAL_SECRET_DIR/server-key.pem" \
  -out "$AUTOMATA_LOCAL_SECRET_DIR/server.csr"

openssl x509 -req -sha256 -days 30 \
  -in "$AUTOMATA_LOCAL_SECRET_DIR/server.csr" \
  -CA "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca.pem" \
  -CAkey "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca-key.pem" \
  -CAcreateserial -copy_extensions copy \
  -out "$AUTOMATA_LOCAL_SECRET_DIR/server-chain.pem"

chmod 0600 "$AUTOMATA_LOCAL_SECRET_DIR"/*-key.pem
```

These files are deliberately disposable and unsuitable for a shared machine or
production environment.

### Prepare three local runners for enrollment

Copy the three examples to an ignored host-specific directory and review every
host, resource, profile, and identity value. Each needs a unique `runner_id`,
the common `default` group, instance-specific state paths, and file-backed TLS
destinations that do not exist yet:

```console
export AUTOMATA_RUNNER_CONFIG_DIR="$(pwd -P)/target/runner-local/config"
install -d -m 0700 -- "$AUTOMATA_RUNNER_CONFIG_DIR"
for instance in 1 2 3; do
  install -m 0600 -- \
    "crates/automata-ci-runner/config/runner.local-${instance}.example.json" \
    "$AUTOMATA_RUNNER_CONFIG_DIR/runner-${instance}.json"
  automata-runner capabilities \
    --config "$AUTOMATA_RUNNER_CONFIG_DIR/runner-${instance}.json"
done
```

Use the [runner configuration reference](../crates/automata-ci-runner/config/README.md)
to finish reviewing the three files, then follow the
[three-process host guide](../deploy/runner-host/README.md) through installation
of the dedicated accounts, reviewed binary and configurations, owner-only spool
keys and service environment, private state roots, and rootless Podman mounts.
Stop before its dynamic-enrollment section until the server and administrator
setup below are complete. Do not pre-create any configured TLS destination or
adjacent enrollment stage. Each TLS directory must be mode `0700` and owned by
its exact service account so enrollment can stage and install that identity
without giving either of the other accounts access.

On Unix, every ordinary server `file:` secret-source reference must be an
absolute path. Automata opens each path component without following symbolic
links and accepts only a regular file owned by the server's effective user,
readable by that owner, with no group or other permission bits. A relative
path, symlink, FIFO, directory, file owned by another user, or mode such as
`0640`/`0644` fails startup. Environment references avoid putting values in
process arguments, but the service manager must still prevent inherited
environment disclosure. Prefer a mounted owner-only secret file or a platform
secret-injection facility for long-running deployments.

## 4. Configure authentication and start the server

### Enable GitHub human authentication for enrollment

Runner enrollment requires GitHub human authentication, and a fresh database
cannot start without one complete installation bootstrap tuple. Create a
GitHub App whose user callback is the external origin plus
`/auth/github/callback`, and enable Device Flow in the App settings. Device
Flow is opt-in and cannot be enabled by an App Manifest. Then create local
keys:

```console
openssl rand 32 > "$AUTOMATA_LOCAL_SECRET_DIR/auth-session-hmac.key"
openssl rand 32 > "$AUTOMATA_LOCAL_SECRET_DIR/auth-wrapping.key"
chmod 0600 "$AUTOMATA_LOCAL_SECRET_DIR"/auth-*.key

export AUTOMATA_EXTERNAL_URL=http://127.0.0.1:8080/
export AUTOMATA_AUTH_ALLOW_LOOPBACK_HTTP=true
export AUTOMATA_GITHUB_CLIENT_ID='replace-with-app-client-id'
export AUTOMATA_GITHUB_CLIENT_SECRET_SOURCE="file:${AUTOMATA_LOCAL_SECRET_DIR}/github-client-secret"
export AUTOMATA_AUTH_SESSION_HASH_KEY_SOURCE="file:${AUTOMATA_LOCAL_SECRET_DIR}/auth-session-hmac.key"
export AUTOMATA_AUTH_ENCRYPTION_KEY_SOURCE="file:${AUTOMATA_LOCAL_SECRET_DIR}/auth-wrapping.key"
export AUTOMATA_AUTH_KEY_ID=local-auth-2026
```

Create `github-client-secret` as an owner-only file; do not export its value or
put it in an option. Create the one-use bootstrap tuple before the first server
start:

```console
openssl rand -hex 32 > "$AUTOMATA_LOCAL_SECRET_DIR/auth-bootstrap.token"
chmod 0600 "$AUTOMATA_LOCAL_SECRET_DIR/auth-bootstrap.token"

export AUTOMATA_BOOTSTRAP_TOKEN_SOURCE="file:${AUTOMATA_LOCAL_SECRET_DIR}/auth-bootstrap.token"
export AUTOMATA_BOOTSTRAP_GITHUB_USER_ID='replace-with-numeric-user-id'
export AUTOMATA_BOOTSTRAP_TENANT_ID=local
export AUTOMATA_BOOTSTRAP_TENANT_DISPLAY_NAME='Local development'
```

`AUTOMATA_BOOTSTRAP_GITHUB_USER_ID` is the permitted user's stable numeric
GitHub ID, not a login. An incomplete tuple or a fresh database without it
fails closed.

### Apply the Results guard and start

A rootless job cannot reach a Results listener bound to host loopback. Follow
the [Arch Linux Results-listener firewall](platforms/arch-linux.md#local-results-listener-firewall)
through its render, route, apply, and audit steps before starting the server.
Choose the exact private address assigned to this host and export it; the
example below uses the address from that guide:

```console
export AUTOMATA_RESULTS_LISTEN_IP=192.168.0.8
```

Never substitute `0.0.0.0`: this development-only HTTP endpoint must be
restricted by the documented host firewall before it starts.

```console
automata server \
  --results-listen "${AUTOMATA_RESULTS_LISTEN_IP}:8081" \
  --results-public-url http://host.containers.internal:8081/ \
  --results-allow-development-http \
  --results-trusted-private-host host.containers.internal \
  --results-signing-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/results-hmac.key" \
  --control-plane-encryption-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/control-plane-wrapping.key" \
  --control-plane-encryption-key-id local-control-plane-2026 \
  --database-url-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/database-url" \
  --database-transport loopback-plaintext \
  --s3-endpoint http://127.0.0.1:9000/ \
  --s3-allow-loopback-http \
  --s3-bucket automata-dev \
  --s3-prefix automata/v1 \
  --s3-kms-key-id default \
  --s3-access-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/s3-access-key" \
  --s3-secret-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/s3-secret-key" \
  --runner-public-url https://127.0.0.1:9090/ \
  --runner-client-ca-cert-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/runner-ca.pem" \
  --runner-client-ca-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/runner-ca-key.pem" \
  --runner-server-ca-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/runner-ca.pem" \
  --runner-server-cert-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/server-chain.pem" \
  --runner-server-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/server-key.pem"
```

Startup applies embedded PostgreSQL migrations, verifies the database, and
performs a conditional immutable write/read probe against RustFS. A failed
dependency prevents the server from becoming ready.

Before enrollment or job execution, return to the firewall guide and complete
its post-start Podman-path capture and separate-LAN denial tests. If either
fails, stop the server before changing or removing the exact guard.

Finish the one-use `/setup` browser flow as the configured GitHub identity
before attempting an ordinary CLI login. Remove the bootstrap tuple from future
server starts after the durable installation reaches `configured`. See
[Authentication and authorization](authentication.md#enable-github-human-authentication)
for the complete state machine.

Loopback HTTP works only because the origin is a literal loopback address and
the development switch is set. Any non-local deployment requires a canonical
HTTPS origin.

The authentication key encrypts GitHub user tokens. The control-plane key from
the base command separately encrypts runner messages and GitHub App service
credentials. Keep both outside PostgreSQL and its backups. See
[Authentication and authorization](authentication.md#enable-github-human-authentication)
for setup state, sessions, and key rotation.

### Enroll the three runners

After completing the one-use browser setup, sign in once through the Linux CLI
and issue a separate 15-minute token for each process. Pipe it directly to the
runner so it does not enter argv or a shell-history assignment. Literal
loopback HTTP is accepted only for this explicit development case:

```console
automata auth --server-url http://127.0.0.1:8080 login
(
  set -euo pipefail
  for instance in 1 2 3; do
    automata runner --server-url http://127.0.0.1:8080 --output json token \
    | jq -er '.token | select(type == "string" and length > 0)' \
    | sudo --user="automata-runner-${instance}" -- \
        /usr/bin/automata-runner enroll \
          --server http://127.0.0.1:8080 \
          --config "/etc/automata-runner/instances/${instance}/runner.json" \
          --name "local-runner-${instance}"
  done

  sudo systemctl daemon-reload
  sudo systemctl enable --now automata-runner-host.target
  systemctl --no-pager --full status \
    automata-runner@1.service \
    automata-runner@2.service \
    automata-runner@3.service
)
```

The runner generates its ECDSA P-256 key locally. The control plane receives a
CSR, registers the exact configuration capabilities, and returns only the
signed client chain and server roots. Tokens are tenant/group scoped, one-use,
and stored only as domain-separated digests. Interrupted enrollment can be
rerun: a private adjacent stage retains the operation and key until all three
credential files are durably reconciled, including when the exact server response
had not yet been staged. The token source is not needed again after that request
stage has been created. A retry must use the exact same server, configuration,
name, and service account, with standard input redirected from `/dev/null`; do
not create a replacement token or delete private staging after an indeterminate
server response. The three services start only after every enrollment succeeds.
See the
[security and lifecycle plan](runner-control-plane-security-and-enrollment.md).

### Optional GitHub provider runtime

Browser OAuth configuration does not enable repository webhook/source/Checks
processing. For that separate runtime, copy the product's checked
[`github-provider.example.json`](../crates/automata-ci/config/github-provider.example.json),
replace every sample identity and nested secret-source reference, install the
manifest as an owner-only regular file, and add this option to the server
command:

```console
--github-provider-config-source file:/etc/automata/github-provider.json
```

The manifest is strict and current-only. Every repository declares its
canonical `default_branch`. The provider derives its full `refs/heads/...`
reference, revisions it in the durable manifest digest, and requires push and
repository-dispatch source selection to agree with it. Changing the configured
default branch therefore requires sequential manifest and policy revisions. Cache
authority uses the same branch only as a read-only fallback after the current
job reference. Public entries require a null private-source
authority; private entries require one. Checks authority is mandatory,
all authority UUIDs are unique, nested authority revisions equal the repository
policy revision, and stable numeric GitHub installation/repository/owner IDs
must match the App installation. The product reference documents every field,
rotation rule, webhook path, and `standard` versus `credential_free` output-
safety choice. Subscribe the App webhook to the configured supported events.
The App's registration-wide permissions are Checks write, Contents read, Pull
requests read, and Merge queues read; internal private-source authority remains
scoped separately per repository. Workflow selection is server-owned and
hardcoded to `all_direct`; it is not a provider-manifest field. That policy
discovers only canonical `.yml` and `.yaml` files directly beneath
`.ci/workflows/` at the exact authenticated source revision; nested files and
other extensions are not selected. Discovery is bounded by the manifest archive
limits, and the sorted inventory and each path-local result are durable before
the delivery completes.

The required top-level `transport` is a closed deployment policy. Production
uses `{"mode":"github_dot_com"}`. The isolated integration suite may instead
use `{"mode":"loopback_emulator","api_base":"http://automata-git.localhost:PORT/api/v3/","job_runtime_origin":"http://automata-git.invalid:PORT/"}`.
The API base is the credential-free loopback control origin. The separately
validated `.invalid` origin is carried only into job repository authority and
must use the same port exposed by the isolated runner mapping. Emulator mode
applies the same bounded protocol clients and never falls back to GitHub.com.
It is an E2E protocol-emulation lane, not evidence that GitHub.com networking
or installation configuration works.

Provider configuration schema 2 requires the top-level `dashboard_url`, the
canonical public Automata origin used for every Check Run `details_url`.
Schema-1 documents must be migrated by adding this field and changing `schema`
to `2`; there is deliberately no guessed provider or dashboard origin.
Production requires a credential-free HTTPS root URL. An isolated emulator may
additionally use an HTTP root URL on a literal loopback address. Workflow Checks
link to the repository activity page, workflow-run Checks link to the exact run,
and job Checks link to the exact concrete job.

Use the provider-facing evaluated job name when configuring a branch-protection
required check or ruleset. Required names must be unique across workflows and
matrix expansions because GitHub matches the Check Run name, not Automata's
workflow path. When GitHub offers multiple Apps as the source for the same
name, select the Automata GitHub App explicitly. Rich Checks are Automata's only
commit/PR result projection. Do not configure or expect a second Commit Status
API context for the same result.

Subscribe the App webhook to `check_run` and `check_suite` in addition to the
configured trigger events. Completed Automata Checks expose native re-run
buttons; their signed webhook payload is resolved against the exact App,
installation, repository, SHA, suite, Check Run, external ID, and current
Automata user authority before the existing idempotent rerun transaction runs.
GitHub provides no iframe slot for an external CI dashboard, so do not weaken
Automata's `frame-ancestors 'none'` policy. The supported native UX is rich
Check output and annotations plus exact external Details links.

The optional top-level `schedule` object controls the separate periodic
workflow scheduler; omitting it uses the documented example defaults. It
enumerates only current manifests in stable order, resolves the configured
default branch to an exact commit, stores a content-addressed archive, and
seals schedule definitions before any due occurrence can run. Public discovery
is anonymous. Private discovery acquires only the matching
`private_repository_source_read` authority with the dedicated
`DiscoverPrivateRepositorySchedules` action; it never accepts or invents a
webhook delivery identity. Each due occurrence has its own fence and atomically
creates its scheduled Check subject with admission. At most
`maximum_fires_per_pass` occurrences are caught up in a pass; occurrences older
than `staleness_millis` are recorded as skipped and their calendar cursor moves
past the trusted claim time.

Repository manifests require numeric `repository_owner_id` evidence and use
repository-wide direct-workflow discovery on the configured default branch.
Never put the App PEM or webhook HMAC bytes in this file.

Set every repository `tenant_id` to the server's one effective UI tenant. With
human authentication enabled, this is the tenant in durable installation state
or the configured bootstrap tenant while setup is active; otherwise it is the
validated fallback tenant, which defaults to `local`. Any provider mismatch
fails startup before the App private key or webhook HMAC is loaded and before
provider manifests or runtime state are constructed. Set the unauthenticated
fallback with `--fallback-tenant-id` or `AUTOMATA_FALLBACK_TENANT_ID`; there is
no tenant chooser or compatibility fallback.

The control-plane wrapping key is mandatory and must contain exactly 32 random
bytes. It envelope-encrypts durable runner commands and RPC responses before
they reach PostgreSQL; those payloads may contain short-lived workload
credentials. The same keyring encrypts durable GitHub App server-service
credentials used by the optional source/Checks runtime. The wrapping key must
live outside PostgreSQL and outside its backups. Protect the host filesystem
that contains mounted key files with encryption at rest, or replace the local
keyring with an equivalent KMS/HSM adapter before treating the deployment as
production. PostgreSQL data files, WAL archives, replicas, snapshots, and
backups also need storage-level encryption and access control: application
envelopes do not protect every non-secret metadata column.

### Managed-secret encryption boundary

The secret-provider SPI and built-in PostgreSQL adapter are implemented. The
optional
`--secret-encryption-key-source`, `--secret-encryption-key-id`, and
`--secret-decryption-key` arguments configure a rotation-aware local keyring. A
complete configuration composes the built-in provider and starts its fenced
cryptographic-erasure cleanup worker; it does not activate the provider. Each
tenant's durable provider is initially seeded unconfigured, and activation is
an explicit, revision-guarded management operation. When human authentication
is also configured, `automata server` exposes authenticated, repository-scoped
HTTP routes for metadata reads, create/replace, delete, provider inspection, and
built-in-provider activation.

This configuration also requires `--runner-public-url` (or
`AUTOMATA_RUNNER_PUBLIC_URL`) set to the exact HTTPS origin used by runner
`control_endpoint` values. The server enables a private binary value route on
that same direct-mTLS listener. Do not terminate this route at the human or
Results proxy.

On the Linux workstation authenticated above, the repository-scoped operator
commands reuse the stored CLI session and require `secret-tool` plus its
unlocked Secret Service:

```console
automata secret --server-url http://127.0.0.1:8080 provider status
automata secret --server-url http://127.0.0.1:8080 provider activate
automata secret --server-url http://127.0.0.1:8080 list --scope repo:OWNER/REPOSITORY
automata secret --server-url http://127.0.0.1:8080 create DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY --from-file /absolute/path/to/value
automata secret --server-url http://127.0.0.1:8080 delete DEPLOY_TOKEN \
  --scope repo:OWNER/REPOSITORY
```

Creation accepts values only from a safe, owner-only `--from-file` path or
redirected standard input, never from a command argument or JSON field. The
current permission combinations are `secrets:metadata:read` for list;
`secrets:metadata:read` plus `secrets:create` for create;
`secrets:metadata:read` plus `secrets:delete` for delete;
`secret-providers:read` for provider status; and `secret-providers:read` plus
`secret-providers:manage` for activation. The CLI has no replacement command
and refuses create when the name already exists. The authenticated repository
Secrets page provides value-free metadata and capability-gated create, replace,
delete, and built-in-provider activation. The built-in provider can deliver an
exact immutable version to a current leased attempt after Store-owned gate,
policy, approval, grant, session, and fence checks. The runner installs the
complete response in zeroizing job-local custody and masks every value before a
separate acknowledgement; cancellation or partial decoding never initiates the
acknowledgement. External and dynamically leased providers remain unsupported. See the
[authentication guide](authentication.md#manage-repository-secrets-from-the-cli) for redirected
input, safe-file, confirmation, and verification details.

The built-in path now fails closed at restart, periodic readiness, and every
write boundary. Immutable authenticated canaries prove loaded bytes for the
active and every durably required wrapping key; absent or mismatched material
blocks provider, API, cleanup, and stale-recovery writes. Cleanup and recovery
use bounded deadlines and monotonic fences, provider state has a
reauthorization-bound read for lost-response recovery, and closed metrics expose
pending, in-progress, and dead-letter cleanup state without identifiers.

The built-in adapter stores immutable values only as authenticated envelope
ciphertext, a nonce, a wrapped data key, and non-secret metadata. Its mutation
ledger reserves a value-free intent, stages an encrypted non-resolvable version,
and confirms the exact winner before advancing the logical head. An external
adapter may instead declare provider-managed encryption, but it must verify that
boundary before composition; the SPI has no plaintext or unspecified mode.

The provider wrapping root must remain outside PostgreSQL and its backups, and
old decrypt-only keys must be
retained until every dependent version has been rewrapped or cryptographically
erased. Storage encryption remains required for database files, WAL, replicas,
snapshots, backups, swap, crash dumps, and host volumes that can contain key
material. See [secret storage](authentication.md#secret-storage)
for the adapter and mutation contracts.

`--database-transport loopback-plaintext` is a development-only exception. It is
rejected unless the effective PostgreSQL target is a Unix socket or literal
loopback IP address; names such as `localhost` and remote hosts fail closed.
Without the exception, Automata forces `sslmode=verify-full` even when the URL
omits `sslmode` or requests a fallback mode. Remote deployments must use a host
name matching the database certificate and configure its trusted CA (for
example with `sslrootcert` in the referenced URL).

### Greenfield database boundary

Only a fresh database initialized by the canonical
`0001_initial_schema.sql` is supported. Never copy, relabel, or reinterpret
plaintext `runner_command_outbox` or `runner_rpc_receipts` retry rows as
current encrypted state. Recreate the database or restore an explicitly
reviewed backup produced by the current encrypted schema.

### Rotating the control-plane wrapping key

Use a new random 32-byte key and a new canonical key ID. Restart every replica
with the new pair as active and the previous pair as decrypt-only. For example,
set these non-secret references in the service manager before invoking the
complete server command:

```console
export AUTOMATA_CONTROL_PLANE_ENCRYPTION_KEY_ID=control-plane-2026-09
export AUTOMATA_CONTROL_PLANE_ENCRYPTION_KEY_SOURCE=file:/run/secrets/automata/control-plane-2026-09.key
export AUTOMATA_CONTROL_PLANE_DECRYPTION_KEYS=control-plane-2026-08=file:/run/secrets/automata/control-plane-2026-08.key
```

New runner-message and GitHub App service-credential envelopes use only the
active key. Old envelopes remain readable through the decrypt-only entry. Do
not remove or retire an old key until no live table row of either kind
references its `wrapping_key_id`, all replicas have converged, and every backup
that could restore an old envelope has expired or retains access to that key.
The current server does not silently rewrap historical rows.

## 5. Verify the server

From another terminal:

```console
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
automata admin status
```

The web interface at <http://127.0.0.1:8080> renders tenant-scoped workflow
runs from PostgreSQL, with verified job logs and finalized artifacts loaded
from immutable blob storage. This composition uses the tenant established by
the completed one-use setup. Human authentication is enabled by the command
above; the server exposes anonymously only data whose durable publication
policy permits it, while private and authenticated views require the configured
GitHub identity and active session.

An authorized browser can change repository access at
`/{owner}/{repository}/settings/access`. Dashboard metadata, logs, and artifacts
each select private, authenticated, or public visibility. Public means anonymous
read-only access and never grants mutation authority. Runs snapshot all three
choices at admission; log and artifact reads remain independent of dashboard
visibility. Attempts whose user code can read a managed secret always narrow
logs and artifacts to private. Registered credential bytes are masked before
stdout/stderr enters persistent ingestion, preserving unrelated diagnostics.

## 6. Exercise configured provider admission

The server exposes no local bearer workflow ingress. To create durable workflow
work, first configure the exact GitHub provider above, then deliver a supported
signed webhook through that provider boundary. In `all_direct` mode, each
selected direct workflow is evaluated independently; an invalid or unselected
workflow cannot suppress a different selected workflow from the same immutable
repository archive.

Admission validates and persists immutable workflow evidence asynchronously.
Its durable receipt does not mean a job has finished: the mandatory autonomous
worker subsequently supervises logical preparation, activation, and
materialization. The full G1 runner, provider, and service-image compatibility
gate remains separate and open.

## Stop and restart

Stop `automata` with `Ctrl-C`, then stop the durable services:

```console
podman-compose --file deploy/dev/compose.yaml down
```

The Compose volumes persist database and object data across restarts. See the
[local infrastructure guide](../deploy/dev/README.md) before deleting them.

## Service-proxy image candidates

CI and the release staging workflow build the private service-proxy helper as a
static executable, generate its SBOM and license payload, build and execute its
scratch image locally, and package a reproducible canonical OCI archive with
source and image provenance. Release staging attests and uploads that raw
candidate as a workflow artifact bound to its OCI manifest digest; it does not
push the image or create a registry tag. A missing candidate digest,
provenance digest, or artifact digest fails release staging.

The candidate is therefore input for a separately reviewed publication step,
not a runnable registry reference. Do not configure a runner from the workflow
artifact name or a transport tag. Publication must preserve the reviewed OCI
manifest digest, after which runners may use only the exact
`registry/repository@sha256:<digest>` reference described in the
[runner bootstrap guide](../crates/automata-ci-runner/config/README.md#optional-service-container-helper).

## Production requirements

A future production deployment must, at minimum:

- use managed or highly available PostgreSQL and S3-compatible storage;
- use fixed nonzero ports for the human, Results, and runner listeners;
- terminate human and Results traffic with HTTPS; when either raw HTTP listener
  is not loopback-only, require an isolating trusted reverse proxy and set the
  corresponding `--human-trusted-reverse-proxy` or
  `--results-trusted-reverse-proxy` deployment assertion;
- expose runner control only through direct TLS 1.3 and client-certificate
  verification, and configure its exact public HTTPS origin when managed-secret
  delivery is enabled;
- store secret values outside process arguments and repository files, and use
  authenticated encryption for all recoverable secret-bearing durable data;
- keep wrapping roots outside the database and encrypt database data, WAL,
  replicas, snapshots, backups, and secret-bearing host volumes at rest;
- operate explicit active/decrypt-only wrapping-key rotation and retain old
  decrypt-only keys until all dependent envelopes are rewrapped or erased;
- give every installation a unique object prefix and Results signing key;
- separate human sessions, runner identity, workload credentials, and storage
  credentials; and
- deploy execution hosts according to their advertised isolation class.

The detailed listener and credential reference is in the
[`automata` README](../crates/automata-ci/README.md). Current product support is
tracked in [Compatibility](compatibility.md); the presence of a flag, manifest,
or release job is not a production-support claim.
