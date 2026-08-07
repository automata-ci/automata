# Local infrastructure

This Compose project contains only Automata's durable development services:
PostgreSQL for transactional control-plane state and RustFS for S3-compatible
objects. Job execution is deliberately not part of this project; the local
runner creates and owns its own rootless Podman resources.

Both images are pinned by release tag and multi-platform manifest digest. The
defaults bind only to loopback and use explicitly development-only credentials.
Override them by copying `.env.example` to `.env` in this directory.

```console
podman-compose --file deploy/dev/compose.yaml up --detach
podman-compose --file deploy/dev/compose.yaml ps
podman-compose --file deploy/dev/compose.yaml down
```

Use `podman-compose` explicitly. If Docker Compose is also installed, the
`podman compose` wrapper prefers it and requires an enabled Podman API socket.

Named volumes intentionally survive `down`. Removing them destroys local
database and object data and is therefore never done by repository scripts.

Default endpoints:

- PostgreSQL: `postgresql://automata:automata-local-only@127.0.0.1:5432/automata`
- S3 API: `http://127.0.0.1:9000`
- RustFS console: `http://127.0.0.1:9001`

The optional local Results listener cannot use loopback because it must be
reachable from rootless job namespaces. Configure one exact private host
address and protect it with the dedicated nftables guard before starting the
listener. The example development values are in
[`results-firewall.env.example`](results-firewall.env.example); render and
inspect the policy without changing the host with:

```console
../../scripts/dev/results-firewall.sh render \
  --config results-firewall.env.example
```

The guarded listener and job-facing URL for those example values are
`192.168.0.8:8081` and `http://host.containers.internal:8081/`. These are local
development settings, not production defaults. The Arch host guide contains
the required packet-path diagnostic, apply/audit/remove procedure, and
fail-closed behavior.

The optional smart-Git bridge used by local dogfood jobs has the same host
reachability constraint, but owns a separate policy and port. It must bind the
one exact private address, never `0.0.0.0`. Render its checked-in example
without changing the host with:

```console
../../scripts/dev/git-bridge-firewall.sh render \
  --config git-bridge-firewall.env.example
```

The example protects `192.168.0.8:8088` in the independent
`inet automata_git_bridge_guard` table. Apply and audit that exact table before
starting `git-http-server.py`; do not reuse, merge, or flush the Results,
container-runtime, or Tailscale tables. The Arch and runner configuration
guides contain the packet-path probe and exact listener command.

These credentials and endpoints are unsuitable for shared or production use.

For Arch Linux host prerequisites and the Netavark/nftables admission check,
see [`docs/platforms/arch-linux.md`](../../docs/platforms/arch-linux.md).
