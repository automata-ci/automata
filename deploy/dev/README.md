# Local durable services

This Compose project runs the two stateful services used by Automata during
development:

- PostgreSQL for durable control-plane state; and
- RustFS for S3-compatible immutable objects.

It does not start `automata`, `automata-runner`, or job sandboxes. The runner
creates and owns its own rootless Podman resources.

## Prerequisites

Install rootless Podman and `podman-compose`. Use the `podman-compose` executable
directly: the `podman compose` wrapper may select Docker Compose and require an
enabled Podman API socket.

The service images are pinned by release and multi-platform digest. Ports bind
to loopback and the default credentials are local-only.

## Start the services

Run from the repository root:

```console
podman-compose --file deploy/dev/compose.yaml up --detach
podman-compose --file deploy/dev/compose.yaml ps
```

Wait until both services report healthy.

## Endpoints

| Service | Address |
| --- | --- |
| PostgreSQL | `postgresql://automata:automata-local-only@127.0.0.1:5432/automata` |
| RustFS S3 API | `http://127.0.0.1:9000` |
| RustFS console | `http://127.0.0.1:9001` |

To change a port or credential, copy `deploy/dev/.env.example` to
`deploy/dev/.env` and edit the copy before starting the project. Do not reuse
these defaults on a shared host.

## Initialize and test the object store

The RustFS contract test creates `automata-dev` if it is missing, then verifies
conditional immutable publication and digest-checked reads:

```console
export AUTOMATA_TEST_S3_ENDPOINT='http://127.0.0.1:9000/'
export AUTOMATA_TEST_S3_BUCKET='automata-dev'
export AUTOMATA_TEST_S3_ACCESS_KEY='automata-local'
export AUTOMATA_TEST_S3_SECRET_KEY='automata-local-secret-change-me'
cargo test -p automata-ci-blob-s3 --test rustfs_contract --all-features --locked -- --ignored
```

For the complete integration-test environment, use the
[development guide](../../docs/development.md). To start the control plane, use
the [control-plane setup](../../docs/deployment.md).

## Stop or reset

Stop the containers without deleting data:

```console
podman-compose --file deploy/dev/compose.yaml down
```

The named volumes intentionally survive `down`. Removing them destroys the
local database and object data, so repository scripts never do that
automatically.

## Job-reachable development listeners

Loopback on the host is not loopback inside a rootless job namespace. The
optional Results listener and smart-Git bridge therefore bind one exact private
host address and are protected by separate nftables policies. Neither listener
may bind `0.0.0.0`.

Render and inspect the example Results policy without changing the host:

```console
./scripts/dev/results-firewall.sh render \
  --config deploy/dev/results-firewall.env.example
```

The checked-in example protects `192.168.0.8:8081` in its own nftables table
and uses `http://host.containers.internal:8081/` as the job-facing URL.

Render the independent smart-Git bridge policy with:

```console
./scripts/dev/git-bridge-firewall.sh render \
  --config deploy/dev/git-bridge-firewall.env.example
```

That example protects `192.168.0.8:8088` in
`inet automata_git_bridge_guard`. Do not merge, reuse, or flush the Results,
Git-bridge, container-runtime, or Tailscale tables.

Applying these policies changes host networking and requires a host-specific
address review. Follow the [Arch Linux runner-host guide](../../docs/platforms/arch-linux.md)
for packet-path diagnostics, apply/audit/remove commands, and fail-closed
behavior.
