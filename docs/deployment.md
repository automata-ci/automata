# Control-plane setup

This guide starts the bootstrap `automata server` composition on one development
machine. It is useful for integration work with the control-plane, runner, and
optional configured GitHub provider boundaries.

> [!CAUTION]
> This is not a production deployment guide. Release packaging does not make
> this bootstrap composition production-ready: automated runner enrollment,
> the complete workflow-to-runner execution path, production retention, and the
> end-to-end compatibility gate are not available yet.

## What you will run

| Component | Default local address | Purpose |
| --- | --- | --- |
| Human HTTP and SSR | `127.0.0.1:8080` | Health, readiness, UI, authentication, and administration |
| Results API | `127.0.0.1:8081` | GitHub Actions Results-compatible requests |
| Runner control | `127.0.0.1:9090` | Direct HTTP/2 with mandatory mutual TLS |
| PostgreSQL | `127.0.0.1:5432` | Durable coordination and metadata |
| RustFS S3 API | `127.0.0.1:9000` | Immutable blobs |
| RustFS console | `127.0.0.1:9001` | Local object-store administration |

You need Git, rustup, OpenSSL, rootless Podman, and `podman-compose`. The
repository checkout supplies the Compose definition, local tests, and example
configuration used below.

## 1. Install Automata and clone the repository

Follow [getting started](getting-started.md#install-automata) to install both
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
cargo test -p automata-ci-blob-s3 --test rustfs_contract --all-features --locked -- --ignored
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

### Bootstrap one static local runner

The v0.1 bootstrap composition has no enrollment API. Its supported initial
runner-admission path is a privileged declarative fleet file loaded at server
startup. Run the non-`sudo` commands below as the dedicated non-root runner
account; the checked-in example assumes UID 1000. The derivation commands also
require Python 3 and GNU coreutils `date`. First make an ignored host-specific
configuration and review every host, resource, profile, and identity value
before deriving its capabilities:

```console
export AUTOMATA_RUNNER_CONFIG="$(pwd -P)/target/runner-local/runner.local.json"
install -d -m 0700 -- "$(dirname "$AUTOMATA_RUNNER_CONFIG")"
install -m 0600 -- \
  crates/automata-ci-runner/config/runner.local.example.json \
  "$AUTOMATA_RUNNER_CONFIG"
```

Follow the [runner bootstrap guide](../crates/automata-ci-runner/config/README.md)
when adapting that file. In particular, it must use a unique canonical
`runner_id`, exactly one runner group, paths and a runtime UID belonging to the
service account, and an inventory that the configured executor can enforce.
The next command validates the complete configuration and emits only the exact
derived durable-registration `RunnerCapabilities` ceiling. Optional abilities
such as service containers appear only when their exact immutable inputs are
configured; the runner still has to prove them during startup, and scheduling
uses the intersection of this registered ceiling with the live session
advertisement. The command validates credential references but does not open
them or read their values:

```console
automata-runner capabilities --config "$AUTOMATA_RUNNER_CONFIG" \
  > "$AUTOMATA_LOCAL_SECRET_DIR/runner-capabilities.json"
```

Create one CA-signed leaf whose extended key usage is exactly `clientAuth`.
The registration loader rejects CA leaves, CA/key-signing usage, missing or
additional extended usages, a PEM containing a certificate chain, and an expiry
that differs from the leaf's exact X.509 `notAfter` value:

```console
umask 077
openssl req -newkey rsa:3072 -nodes -sha256 \
  -subj '/CN=Automata local static runner' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=critical,clientAuth' \
  -keyout "$AUTOMATA_LOCAL_SECRET_DIR/runner-key.pem" \
  -out "$AUTOMATA_LOCAL_SECRET_DIR/runner.csr"

openssl x509 -req -sha256 -days 30 \
  -in "$AUTOMATA_LOCAL_SECRET_DIR/runner.csr" \
  -CA "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca.pem" \
  -CAkey "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca-key.pem" \
  -CAserial "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca.srl" \
  -copy_extensions copy \
  -out "$AUTOMATA_LOCAL_SECRET_DIR/runner.pem"

runner_cert_not_after="$(
  LC_ALL=C date --utc --date="$(
    LC_ALL=C openssl x509 -in "$AUTOMATA_LOCAL_SECRET_DIR/runner.pem" \
      -noout -enddate | sed 's/^notAfter=//'
  )" +%s
)"
```

Build the static fleet document from that canonical output instead of copying
the JSON file's input inventory. This example binds the runner to the example
tenant `local` and requires the capabilities to name exactly one group:

```console
python3 - \
  "$AUTOMATA_LOCAL_SECRET_DIR/runner-capabilities.json" \
  "$runner_cert_not_after" \
  > "$AUTOMATA_LOCAL_SECRET_DIR/static-runners.json" <<'PY'
import json
import sys
import time

with open(sys.argv[1], encoding="utf-8") as source:
    capabilities = json.load(source)

groups = capabilities.get("groups")
if not isinstance(groups, list) or len(groups) != 1:
    raise SystemExit("runner capabilities must name exactly one group")
expires_at_seconds = int(sys.argv[2])
if expires_at_seconds <= int(time.time()):
    raise SystemExit("runner certificate must expire in the future")

runner_id = capabilities["runner_id"]
document = {
    "schema_version": 1,
    "tenant": "local",
    "group": groups[0],
    "runners": [{
        "id": runner_id,
        "name": "local-runner",
        "external_identity": f"local-static:{runner_id}",
        "labels": capabilities["labels"],
        "capabilities": capabilities,
        "slots": capabilities["max_parallel_jobs"],
        "active_client_certificates": [{
            "source": "file:/etc/automata/bootstrap/runner.pem",
            "expires_at_seconds": expires_at_seconds,
        }],
    }],
}
json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
```

The server-side leaf and fleet document have a stricter trust boundary than
ordinary secret files: every ancestor is root-owned and not group- or
world-writable, and each file is root-owned, single-linked, and has no write
bits. Install separate copies so the runner can keep its private key owner-only:

```console
export AUTOMATA_RUNNER_USER="$(id -un)"
export AUTOMATA_RUNNER_GROUP="$(id -gn)"
test "$(id -u)" -ne 0

sudo install -d -o root -g root -m 0755 \
  /etc/automata /etc/automata/bootstrap
sudo install -o root -g root -m 0444 \
  "$AUTOMATA_LOCAL_SECRET_DIR/runner.pem" \
  /etc/automata/bootstrap/runner.pem
sudo install -o root -g root -m 0444 \
  "$AUTOMATA_LOCAL_SECRET_DIR/static-runners.json" \
  /etc/automata/bootstrap/static-runners.json

sudo install -d -o root -g root -m 0755 \
  /etc/automata-runner /etc/automata-runner/tls
sudo install -o root -g root -m 0444 \
  "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca.pem" \
  /etc/automata-runner/tls/server-ca.pem
sudo install -o root -g root -m 0444 \
  "$AUTOMATA_LOCAL_SECRET_DIR/runner.pem" \
  /etc/automata-runner/tls/runner.pem
sudo install -o "$AUTOMATA_RUNNER_USER" -g "$AUTOMATA_RUNNER_GROUP" -m 0600 \
  "$AUTOMATA_LOCAL_SECRET_DIR/runner-key.pem" \
  /etc/automata-runner/tls/runner-key.pem
```

The server loads this exact fleet after migrations and before readiness.
Reapplying an unchanged document is idempotent; membership, identity, routing,
slot, or capability drift aborts startup. Certificate rotation is coordinated:
publish old and new leaves together (at most two), restart every server replica,
switch and restart the runner, then omit the old leaf and restart every server
replica again. Omission revokes the old digest and a stale document cannot
restore it.

Static registration and TLS identity alone do not make the execution host
runnable. Before invoking `automata-runner run`, finish the runner guide's
owner-only spool key, S3 credentials, private state roots, rootless Podman host,
immutable profile, repository bridge, and static-binary requirements.

On Unix, every ordinary server `file:` secret-source reference must be an
absolute path. Automata opens each path component without following symbolic
links and accepts only a regular file owned by the server's effective user,
readable by that owner, with no group or other permission bits. A relative
path, symlink, FIFO, directory, file owned by another user, or mode such as
`0640`/`0644` fails startup. The privileged static registration document and
its referenced leaf are the root-owned, write-bit-free exception governed by
the stricter rules above. Environment references avoid putting values in
process arguments, but the service manager must still prevent inherited
environment disclosure. Prefer a mounted owner-only secret file or a platform
secret-injection facility for long-running deployments.

## 4. Start the server

```console
automata server \
  --results-public-url http://127.0.0.1:8081/ \
  --results-allow-development-http \
  --results-signing-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/results-hmac.key" \
  --control-plane-encryption-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/control-plane-wrapping.key" \
  --control-plane-encryption-key-id local-control-plane-2026 \
  --database-url-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/database-url" \
  --database-transport loopback-plaintext \
  --s3-endpoint http://127.0.0.1:9000/ \
  --s3-allow-loopback-http \
  --s3-bucket automata-dev \
  --s3-prefix automata/v1 \
  --s3-access-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/s3-access-key" \
  --s3-secret-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/s3-secret-key" \
  --runner-client-ca-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/runner-ca.pem" \
  --runner-server-cert-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/server-chain.pem" \
  --runner-server-key-source "file:${AUTOMATA_LOCAL_SECRET_DIR}/server-key.pem" \
  --static-runner-registration-file /etc/automata/bootstrap/static-runners.json
```

Startup applies embedded PostgreSQL migrations, verifies the database, and
performs a conditional immutable write/read probe against RustFS. A failed
dependency prevents the server from becoming ready.

### Optional GitHub human authentication

The local command above intentionally leaves human authentication disabled. To
exercise the composed GitHub boundary, first create a GitHub App whose user
authorization callback is the exact external-origin callback
`/auth/github/callback`. Then add the complete base configuration to every
replica:

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

This authentication wrapping key encrypts human GitHub OAuth access and
refresh tokens stored for browser/device identity and membership refresh. It
does not encrypt GitHub App installation credentials used by repository
webhook/source/Checks processing; those use the separate mandatory
control-plane wrapping key described below.

With those variables exported, restart the complete server command from the
beginning of this section.

The example assumes an owner-only `github-client-secret` file already exists.
Do not export the client secret as the shell variable shown for the non-secret
client ID, and do not place it directly in an option. Plain HTTP authentication
is accepted only because both the external origin and listener are literal
loopback and the explicit development switch is present. Production requires a
canonical HTTPS root origin and omits that switch.

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

The manifest is strict and current-only. Public entries require a null private-
source authority; private entries require one. Checks authority is mandatory,
all authority UUIDs are unique, nested authority revisions equal the repository
policy revision, and stable numeric GitHub installation/repository/owner IDs
must match the App installation. The product reference documents every field,
rotation rule, webhook path, and `standard` versus `credential_free` output-
safety choice. Subscribe the App webhook to `push`, grant `checks:write` for
every registered repository, and grant `contents:read` only for Private source.
The current delivery manifest admits only `.github/workflows/ci.yml` on
`refs/heads/main` for `push`; every other workflow, ref, or event fails closed.
Never put the App PEM or webhook HMAC bytes in this file.

Set every repository `tenant_id` to the server's one effective UI tenant. With
human authentication enabled, this is the tenant in durable installation state
or the configured bootstrap tenant while setup is active; otherwise it is the
validated fallback tenant, which defaults to `local`. Any provider mismatch
fails startup before the App private key or webhook HMAC is loaded and before
provider manifests or runtime state are constructed. Set the unauthenticated
fallback with `--fallback-tenant-id` or `AUTOMATA_FALLBACK_TENANT_ID`; there is
no tenant chooser or compatibility fallback.

For a fresh database, also provide one complete installation tuple:

```console
openssl rand -hex 32 > "$AUTOMATA_LOCAL_SECRET_DIR/auth-bootstrap.token"
chmod 0600 "$AUTOMATA_LOCAL_SECRET_DIR/auth-bootstrap.token"

export AUTOMATA_BOOTSTRAP_TOKEN_SOURCE="file:${AUTOMATA_LOCAL_SECRET_DIR}/auth-bootstrap.token"
export AUTOMATA_BOOTSTRAP_GITHUB_USER_ID='replace-with-numeric-user-id'
export AUTOMATA_BOOTSTRAP_TENANT_ID=local
export AUTOMATA_BOOTSTRAP_TENANT_DISPLAY_NAME='Local development'
```

`AUTOMATA_BOOTSTRAP_GITHUB_USER_ID` is the permitted user's stable numeric
GitHub ID, not a login. The tuple arms a one-use challenge and can be removed
after the durable installation reaches `configured`. While the installation is
armed, the exact `/setup` page exposes the proof-bound browser setup flow; it is
withdrawn immediately after setup completes. Device setup remains API-only and
there is no setup CLI. The
[authentication guide](authentication.md#enable-github-human-authentication)
describes that lifecycle. An incomplete tuple or an unconfigured database with
no tuple prevents startup.

After setup has completed, a Linux workstation with `secret-tool` and an
unlocked Secret Service can verify the CLI-audience path:

```console
automata auth --server-url http://127.0.0.1:8080 login
automata auth --server-url http://127.0.0.1:8080 status
automata auth --server-url http://127.0.0.1:8080 logout
```

The client has no plaintext credential-file fallback. It commits the device
credential to Secret Service before activating the server's short-lived
pending session. The selected Secret Service must itself provide encrypted
backing storage; Automata cannot attest how that external keyring persists its
database.

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
delete, and built-in-provider activation. Runner delivery and external providers
remain unsupported, so jobs do not receive managed secret values. See the
[authentication guide](authentication.md#repository-secret-cli) for redirected
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
material. See [encrypted-at-rest secret providers](authentication.md#encrypted-at-rest-secret-providers)
for the adapter and mutation contracts.

`--database-transport loopback-plaintext` is a development-only exception. It is
rejected unless the effective PostgreSQL target is a Unix socket or literal
loopback IP address; names such as `localhost` and remote hosts fail closed.
Without the exception, Automata forces `sslmode=verify-full` even when the URL
omits `sslmode` or requests a fallback mode. Remote deployments must use a host
name matching the database certificate and configure its trusted CA (for
example with `sslrootcert` in the referenced URL).

### Unsupported pre-release plaintext state

Migration `0013_encrypted_runner_payloads.sql` deliberately fails with SQLSTATE
`23514` if an obsolete pre-release database contains plaintext
`runner_command_outbox` or `runner_rpc_receipts` rows. It never deletes a row or
labels plaintext as encrypted. Such a database is not an upgrade source for
v0.1: stop the obsolete installation and create a fresh current schema, or
restore an explicitly reviewed backup that already uses the current encrypted
schema. Do not bypass the guard or delete individual retry rows in place.

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
from immutable blob storage. This bootstrap composition uses the configured
fallback tenant and exposes only data whose durable publication policy permits
anonymous access. The command above intentionally leaves optional human
authentication disabled. Private and authenticated views require the complete
human-auth configuration and, for a new installation, the
[one-use bootstrap tuple](#optional-github-human-authentication).

An authorized browser can change repository access at
`/{owner}/{repository}/settings/access`. Dashboard metadata, logs, and artifacts
each select private, authenticated, or public visibility. Public means anonymous
read-only access and never grants mutation authority. Runs snapshot all three
choices at admission; log and artifact reads remain independent of dashboard
visibility. Attempts whose user code can read a managed secret always narrow
logs and artifacts to private, and their raw stdout/stderr is suppressed before
persistent ingestion.

## 6. Exercise configured provider admission

The server exposes no local bearer workflow ingress. To create durable workflow
work, first configure the exact GitHub provider above, then deliver a supported
signed `push` webhook for `.github/workflows/ci.yml` on `refs/heads/main`
through that provider boundary.

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
  verification;
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

The current bootstrap build composes opt-in GitHub browser login, device-flow
HTTP endpoints, envelope-encrypted login/provider state, hashed browser/CLI
session credentials, request authentication, repository publication settings,
and the RBAC management HTTP API when the complete configuration is present. A
new installation additionally requires the one-use bootstrap tuple; an
already-configured installation does not. The Linux `automata auth` device
login/status/logout client is operational through Secret Service, and the
authenticated browser Access pages compose RBAC management. The CLI does not
offer web login, and dedicated RBAC CLI commands remain uncomposed. Complete
GitHub provider configuration composes the exact signed webhook, public/private
source delivery, fenced Check Runs, scoped App-credential runtime, and exact
lease-bound repository authority for an already-materialized Standard GitHub
job. CredentialFree jobs receive no runtime authority, and there is no
fallback/default installation route. The mandatory autonomous worker discovers
durable admitted work and supervises logical preparation, activation, and
materialization; admission remains asynchronous and is not a completion signal.
Repository-secret HTTP routes, built-in-provider activation, and
cryptographic-erasure cleanup are composed when their complete configuration is
present. The repository-scoped Linux CLI supports secret list/create/delete and
provider status/activation through its Secret Service-backed session. The
authenticated repository UI additionally supports capability-gated replacement
without ever serializing stored values. External providers and runner secret
delivery remain unsupported. Until delivery is complete, jobs do not receive
managed secrets; readable-secret output is designed to remain suppressed and
fail-private rather than becoming anonymously publishable. The fail-closed
key-custody and worker contract is detailed in
[Managed-secret encryption boundary](#managed-secret-encryption-boundary).

The detailed listener and credential contract lives in the
[`automata` control-plane reference](../crates/automata-ci/README.md). Do not
infer production support from the release artifacts or configuration surface
while the project remains in bootstrap development.
