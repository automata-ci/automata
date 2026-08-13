# Control-plane setup

This guide starts `automata server`, PostgreSQL, RustFS, and three statically
registered runner processes on a development machine. Optional sections add
GitHub login, provider ingress, and the built-in secret provider.

> [!CAUTION]
> This is not a production deployment. Runner enrollment is static, production
> retention is incomplete, and the end-to-end compatibility gate is still open.

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

### Bootstrap three static local runners

The bootstrap composition has no enrollment API. Its supported initial
runner-admission path is one privileged declarative fleet file loaded at server
startup. A Linux host runs exactly three independent single-slot processes.
Run the non-`sudo` derivation commands below from one private non-root staging
account. The deployed host uses three separate service accounts (the checked-in
units use UID/GID pairs 1001 through 1003). Python 3 and GNU coreutils `date`
are also required.

Copy all three examples to an ignored host-specific directory and review every
host, resource, profile, and identity value:

```console
export AUTOMATA_RUNNER_CONFIG_DIR="$(pwd -P)/target/runner-local/config"
install -d -m 0700 -- "$AUTOMATA_RUNNER_CONFIG_DIR"
for instance in 1 2 3; do
  install -m 0600 -- \
    "crates/automata-ci-runner/config/runner.local-${instance}.example.json" \
    "$AUTOMATA_RUNNER_CONFIG_DIR/runner-${instance}.json"
done
```

Follow the [runner bootstrap guide](../crates/automata-ci-runner/config/README.md)
when adapting those files. Each needs a unique canonical `runner_id`, exactly
one common runner group, instance-specific durable/transient paths and
credentials, and `max_parallel_jobs: 1`. The next loop validates each complete
configuration and emits its exact durable-registration `RunnerCapabilities`
ceiling. It validates credential references but does not open their values:

```console
for instance in 1 2 3; do
  automata-runner capabilities \
    --config "$AUTOMATA_RUNNER_CONFIG_DIR/runner-${instance}.json" \
    > "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}-capabilities.json"
done
```

Issue three different CA-signed leaves whose extended key usage is exactly
`clientAuth`. A leaf or private key must never be reused between runner IDs.
The registration loader rejects CA leaves, CA/key-signing usage, missing or
additional extended usages, a PEM certificate chain, and an expiry that differs
from the leaf's exact X.509 `notAfter` value:

```console
umask 077
for instance in 1 2 3; do
  openssl req -newkey rsa:3072 -nodes -sha256 \
    -subj "/CN=Automata local static runner ${instance}" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=critical,clientAuth' \
    -keyout "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}-key.pem" \
    -out "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}.csr"

  openssl x509 -req -sha256 -days 30 \
    -in "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}.csr" \
    -CA "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca.pem" \
    -CAkey "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca-key.pem" \
    -CAserial "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca.srl" \
    -copy_extensions copy \
    -out "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}.pem"

  LC_ALL=C date --utc --date="$(
    LC_ALL=C openssl x509 \
      -in "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}.pem" \
      -noout -enddate | sed 's/^notAfter=//'
  )" +%s > "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}-not-after"
done
```

Build one static fleet document from all three canonical outputs. The builder
requires one common group, future certificate expiries, unique runner IDs, and
exactly one slot per process:

```console
python3 - "$AUTOMATA_LOCAL_SECRET_DIR" \
  > "$AUTOMATA_LOCAL_SECRET_DIR/static-runners.json" <<'PY'
import json
import pathlib
import sys
import time

root = pathlib.Path(sys.argv[1])
now = int(time.time())
runners = []
fleet_group = None
seen_ids = set()

for instance in range(1, 4):
    with (root / f"runner-{instance}-capabilities.json").open(
        encoding="utf-8"
    ) as source:
        capabilities = json.load(source)

    groups = capabilities.get("groups")
    if not isinstance(groups, list) or len(groups) != 1:
        raise SystemExit(f"runner {instance} capabilities must name one group")
    if fleet_group is None:
        fleet_group = groups[0]
    elif groups[0] != fleet_group:
        raise SystemExit("all three runners must use one fleet group")
    if capabilities.get("max_parallel_jobs") != 1:
        raise SystemExit(f"runner {instance} must advertise exactly one slot")

    runner_id = capabilities["runner_id"]
    if runner_id in seen_ids:
        raise SystemExit("runner IDs must be unique")
    seen_ids.add(runner_id)
    expires_at_seconds = int(
        (root / f"runner-{instance}-not-after").read_text(encoding="ascii")
    )
    if expires_at_seconds <= now:
        raise SystemExit(f"runner {instance} certificate must be current")

    runners.append({
        "id": runner_id,
        "name": f"local-runner-{instance}",
        "external_identity": f"local-static:{runner_id}",
        "labels": capabilities["labels"],
        "capabilities": capabilities,
        "slots": 1,
        "active_client_certificates": [{
            "source": f"file:/etc/automata/bootstrap/runner-{instance}.pem",
            "expires_at_seconds": expires_at_seconds,
        }],
    })

document = {
    "schema_version": 1,
    "tenant": "local",
    "group": fleet_group,
    "runners": runners,
}
json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
```

The three processes expose three jobs in aggregate. At the checked-in per-job
ceiling, the host needs at least 12,000 CPU millicores, 48 GiB of job memory,
and 12,288 job PIDs, plus runner, Podman, and operating-system overhead. Keep
every static `slots` value equal to its configuration's
`max_parallel_jobs: 1`; increasing one process to three slots would create
five host jobs rather than the requested three.

The server-side leaves and fleet document have a stricter trust boundary than
ordinary secret files: every ancestor is root-owned and not group- or
world-writable, and each file is root-owned, single-linked, and has no write
bits. Install separate copies so each runner can keep its private key
owner-only:

```console
test "$(id -u)" -ne 0

sudo install -d -o root -g root -m 0755 \
  /etc/automata /etc/automata/bootstrap
for instance in 1 2 3; do
  sudo install -o root -g root -m 0444 \
    "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}.pem" \
    "/etc/automata/bootstrap/runner-${instance}.pem"
done
sudo install -o root -g root -m 0444 \
  "$AUTOMATA_LOCAL_SECRET_DIR/static-runners.json" \
  /etc/automata/bootstrap/static-runners.json

sudo install -d -o root -g root -m 0755 \
  /etc/automata-runner /etc/automata-runner/instances
for instance in 1 2 3; do
  runner_account="automata-runner-${instance}"
  sudo install -d -o root -g "$runner_account" -m 0750 \
    "/etc/automata-runner/instances/${instance}" \
    "/etc/automata-runner/instances/${instance}/tls" \
    "/etc/automata-runner/instances/${instance}/secrets"
  sudo install -o root -g root -m 0444 \
    "$AUTOMATA_LOCAL_SECRET_DIR/runner-ca.pem" \
    "/etc/automata-runner/instances/${instance}/tls/server-ca.pem"
  sudo install -o root -g root -m 0444 \
    "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}.pem" \
    "/etc/automata-runner/instances/${instance}/tls/runner.pem"
  sudo install \
    -o "$runner_account" -g "$runner_account" -m 0600 \
    "$AUTOMATA_LOCAL_SECRET_DIR/runner-${instance}-key.pem" \
    "/etc/automata-runner/instances/${instance}/tls/runner-key.pem"
done
```

The server loads this exact fleet after migrations and before readiness.
Reapplying an unchanged document is idempotent; membership, identity, routing,
slot, or capability drift aborts startup. Certificate rotation is coordinated:
publish each affected runner's old and new leaves together (at most two),
restart every server replica, switch and restart that runner process, then omit
the old leaf and restart every server replica again. Omission revokes the old
digest and a stale document cannot restore it.

Static registration and TLS identity alone do not make the execution host
runnable. Before enabling the three-process target, finish the runner guide's
three owner-only spool keys, service credentials, private state roots, rootless
Podman mounts, immutable profile, repository bridge, and static-binary
requirements. The checked-in [host units](../deploy/runner-host/README.md)
encode the exact three-service lifecycle and aggregate cgroup budget.

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

The base command leaves human authentication disabled. To enable it, create a
GitHub App whose user callback is the external origin plus
`/auth/github/callback`, then create local keys:

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
put it in an option. Restart the complete server command with these variables.
Loopback HTTP works only because the origin is a literal loopback address and
the development switch is set. Any non-local deployment requires a canonical
HTTPS origin.

The authentication key encrypts GitHub user tokens. The control-plane key from
the base command separately encrypts runner messages and GitHub App service
credentials. Keep both outside PostgreSQL and its backups. See
[Authentication and authorization](authentication.md#enable-github-human-authentication)
for setup state, sessions, and key rotation.

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
safety choice. Subscribe the App webhook to the configured supported events,
grant `checks:write` for every registered repository, and grant `contents:read`
only for Private source. The checked-in example uses the server-owned
`{"mode":"all_direct"}` workflow selection. It discovers only canonical
`.yml` and `.yaml` files directly beneath `.ci/workflows/` at the exact
authenticated source revision; nested files and other extensions are not
selected. Discovery is bounded by the manifest archive limits, and the sorted
inventory and each path-local result are durable before the delivery completes.

The required top-level `transport` is a closed deployment policy. Production
uses `{"mode":"github_dot_com"}`. The isolated integration suite may instead
use `{"mode":"loopback_emulator","api_base":"http://automata-git.localhost:PORT/api/v3/","job_runtime_origin":"http://automata-git.invalid:PORT/"}`.
The API base is the credential-free loopback control origin. The separately
validated `.invalid` origin is carried only into job repository authority and
must use the same port exposed by the isolated runner mapping. Emulator mode
applies the same bounded protocol clients and never falls back to GitHub.com.
It is an E2E protocol-emulation lane, not evidence that GitHub.com networking
or installation configuration works.

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
