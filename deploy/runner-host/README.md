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

Install the reviewed binary, units, and private directory declarations as root:

```console
runner_binary="$(command -v automata-runner)"
test -n "$runner_binary"
sudo install -o root -g root -m 0755 "$runner_binary" /usr/bin/automata-runner
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

The instance directory and configuration remain root-owned. Each `tls`
directory is instead mode `0700` and owned by its exact runner account because
that account creates its private enrollment stage, key, returned chain, and
server roots there. The parent instance directory is not writable by the runner,
and no other runner account can traverse the TLS directory. Do not change the
TLS directory to a shared group-writable location and do not run enrollment as
root or as the interactive operator.

The three 20 GiB `tmpfs,noswap` mounts are separate capacity boundaries. They
preserve the runner's exact-mount proof and prevent any instance from sharing
Podman runtime or storage with another. They are transient provider storage,
not advertised per-job disk quota; both `ephemeral_disk_bytes` values remain
zero.

Install one reviewed configuration per instance. Set
`AUTOMATA_RUNNER_CONFIG_DIR` to the absolute ignored directory containing the
three edited `runner-N.json` files; do not install the checked-in examples
without reviewing their host-specific values. In particular, replace each
runner ID, endpoint, profile digest/image, Git bridge, resource ceiling, and
object-store setting as appropriate. Keep all instance-qualified paths and
ports distinct, then install those reviewed copies:

```console
test -n "${AUTOMATA_RUNNER_CONFIG_DIR:-}"
test "$AUTOMATA_RUNNER_CONFIG_DIR" = "$(realpath "$AUTOMATA_RUNNER_CONFIG_DIR")"
for instance in 1 2 3; do
  sudo install -o root -g "automata-runner-${instance}" -m 0640 \
    "$AUTOMATA_RUNNER_CONFIG_DIR/runner-${instance}.json" \
    "/etc/automata-runner/instances/${instance}/runner.json"
  sudo install -o root -g root -m 0600 /dev/null \
    "/etc/automata-runner/instances/${instance}/environment"
done
```

Write the required S3 variables to each owner-only `environment` file; systemd
reads that file before changing to the runner account.

## Provision non-TLS runner inputs

Do not issue or install runner TLS leaves or keys manually. Do not create
`server-ca.pem`, `runner.pem`, `runner-key.pem`, or any adjacent enrollment
stage. The dynamic enrollment step below must observe all three configured TLS
destinations as absent and creates them without overwriting.

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

Validate the installed configurations as the identities that will run them.
This checks the immutable capability documents but does not create a
registration or contact the control plane:

```console
for instance in 1 2 3; do
  sudo --user="automata-runner-${instance}" -- \
    /usr/bin/automata-runner capabilities \
      --config "/etc/automata-runner/instances/${instance}/runner.json" \
    > /dev/null
done
```

## Dynamically enroll three independent identities

Complete the control-plane guide through administrator setup and the operator
CLI login before continuing. The operator creates one short-lived token at a
time, but the exact service account consumes it from standard input and creates
its own key and private adjacent request stage. The token and key never enter a
command argument, the configuration, or another account's custody:

```console
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
)
```

Use the canonical HTTPS control-plane origin outside the explicit literal-
loopback development case. Keep each runner name stable across recovery. If an
enrollment was interrupted after its request stage was created, rerun the exact
same `automata-runner enroll` command as the same service account with standard
input redirected from `/dev/null`; the private stage retains the one-use token,
operation, and key. Do not mint a replacement token or delete a stage whose
server outcome is unknown. A retry fails safely when no matching stage exists.

After each successful enrollment, the TLS directory contains the service-
account-owned server roots and client chain plus a mode-`0600` private key. The
private request and response stages are removed only after all three final files
are durably reconciled. The service-account-owned process lock remains adjacent
to prevent concurrent enrollment against the same destinations.

## Start and observe the trio

Only after all three enrollments succeed, enable the target and verify every
service:

```console
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
