# Three-process Linux runner host

These units provision exactly three independent, single-slot
`automata-runner` processes on one Linux host. The three processes are not
threads or slots of one runner identity. Each instance has its own operating-
system account, runner ID, client leaf and private key, spool key and protection
ID, journal, spool, Podman home and state, delegated service cgroup, and metrics
listener.

The checked-in examples are:

| Instance | Configuration | Metrics | Podman runtime mount |
| --- | --- | --- | --- |
| `1` | `runner.local-1.example.json` | `127.0.0.1:9464` | `/run/automata_runner_1` |
| `2` | `runner.local-2.example.json` | `127.0.0.1:9465` | `/run/automata_runner_2` |
| `3` | `runner.local-3.example.json` | `127.0.0.1:9466` | `/run/automata_runner_3` |

Every configuration advertises `max_parallel_jobs: 1`. At the checked-in
per-job ceiling, the host therefore advertises three jobs in aggregate:
12,000 CPU millicores, 48 GiB of job memory, and 12,288 job PIDs. The units
reserve bounded supervisor overhead and cap the aggregate slice at 13.5 CPU
cores, 54 GiB, and 13,824 tasks. Do not increase a runner's slot count. Change
the three per-job ceilings and both the per-service and aggregate cgroup limits
together when adapting the host.

## Install the host shape

The examples assume dedicated `automata-runner-1`, `automata-runner-2`, and
`automata-runner-3` accounts with matching UID/GID pairs 1001 through 1003,
Linux 6.4 or newer, unified cgroup v2, and the rootless Podman prerequisites
from the [Arch Linux host guide](../../docs/platforms/arch-linux.md). Give every
account a non-overlapping subordinate UID/GID range. If account IDs differ,
update the matching `uid=` and `gid=` in each mount unit before installation.
Do not collapse the services onto one shared account: an instance must not be
able to read another runner's TLS key, spool key, or durable state.

Create the three locked service identities using the host's account-management
policy before applying tmpfiles. A direct Arch Linux example is:

```console
for instance in 1 2 3; do
  sudo groupadd --system --gid "$((1000 + instance))" \
    "automata-runner-${instance}"
  sudo useradd --system --uid "$((1000 + instance))" \
    --gid "automata-runner-${instance}" \
    --home-dir "/var/lib/automata-runner/${instance}/home" \
    --shell /usr/bin/nologin "automata-runner-${instance}"
done
```

Install the binary, units, and private directory declarations as root:

```console
sudo install -o root -g root -m 0755 automata-runner /usr/bin/automata-runner
sudo install -o root -g root -m 0644 \
  deploy/runner-host/systemd/automata-runner@.service \
  deploy/runner-host/systemd/automata-runner-host.slice \
  deploy/runner-host/systemd/automata-runner-host.target \
  deploy/runner-host/systemd/run-automata_runner_1.mount \
  deploy/runner-host/systemd/run-automata_runner_2.mount \
  deploy/runner-host/systemd/run-automata_runner_3.mount \
  /etc/systemd/system/
sudo install -o root -g root -m 0644 \
  deploy/runner-host/systemd/automata-runner-host.tmpfiles \
  /etc/tmpfiles.d/automata-runner-host.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/automata-runner-host.conf
```

The three 20 GiB `tmpfs,noswap` mounts are separate capacity boundaries. They
preserve the runner's exact-mount proof and prevent any instance from sharing
Podman runtime or storage with another. They are transient provider storage,
not advertised per-job disk quota; both `ephemeral_disk_bytes` values remain
zero.

Install one reviewed configuration per instance:

```console
for instance in 1 2 3; do
  sudo install -o root -g "automata-runner-${instance}" -m 0640 \
    "crates/automata-ci-runner/config/runner.local-${instance}.example.json" \
    "/etc/automata-runner/instances/${instance}/runner.json"
  sudo install -o root -g root -m 0600 /dev/null \
    "/etc/automata-runner/instances/${instance}/environment"
done
```

Review every example before starting it. In particular, replace its runner
ID, endpoints, profile digest/image, Git bridge, resources, and object-store
settings as appropriate. Keep all instance-qualified paths and ports distinct.
Write the required S3 variables to each owner-only `environment` file; systemd
reads that file before changing to the runner account.

## Provision three independent identities

Issue three different CA-signed `clientAuth` leaves and keys. A leaf or private
key must never be reused between instances. Install the common server CA and
the instance leaf/key beneath each instance boundary:

```console
for instance in 1 2 3; do
  sudo install -o root -g root -m 0444 server-ca.pem \
    "/etc/automata-runner/instances/${instance}/tls/server-ca.pem"
  sudo install -o root -g root -m 0444 "runner-${instance}.pem" \
    "/etc/automata-runner/instances/${instance}/tls/runner.pem"
  sudo install \
    -o "automata-runner-${instance}" -g "automata-runner-${instance}" -m 0600 \
    "runner-${instance}-key.pem" \
    "/etc/automata-runner/instances/${instance}/tls/runner-key.pem"
done
```

Generate and install a different 32-byte spool key for each instance. The
example protection IDs are also distinct, so ciphertext cannot silently move
between runner spools:

```console
umask 077
for instance in 1 2 3; do
  openssl rand -hex 32 > "spool-key-${instance}.hex"
  sudo install \
    -o "automata-runner-${instance}" -g "automata-runner-${instance}" -m 0600 \
    "spool-key-${instance}.hex" \
    "/etc/automata-runner/instances/${instance}/secrets/spool-key-v1.hex"
done
```

Run `automata-runner capabilities --config ...` once for each configuration
and build one server static-fleet document containing all three results. Every
entry needs the matching runner ID, a distinct name and external identity,
`slots: 1`, and the digest of its own active client leaf. The store deliberately
allows only one live session per runner ID, so starting three processes against
one registration is invalid.

## Start and observe the trio

Validate each configuration as the service account, then enable the target:

```console
for instance in 1 2 3; do
  sudo -u "automata-runner-${instance}" /usr/bin/automata-runner capabilities \
    --config "/etc/automata-runner/instances/${instance}/runner.json" \
    > /dev/null
done
sudo systemctl daemon-reload
sudo systemctl enable --now automata-runner-host.target
systemctl --no-pager --full status \
  automata-runner@1.service \
  automata-runner@2.service \
  automata-runner@3.service
```

Deploy one node-local Prometheus Agent from
[`runner-agent.yml`](../observability/runner-agent.yml). It scrapes all three
fixed loopback ports and attaches three globally unique runner identities plus
one stable shared host identity. The authoritative inventory schema rejects a
host unless it contains exactly runner slots 1, 2, and 3.

Stop or restart an individual service only for instance-local maintenance.
Use `automata-runner-host.target` when the host is intentionally drained or
retired so unit and mount lifecycle remain ordered.
