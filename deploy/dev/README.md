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

These credentials and endpoints are unsuitable for shared or production use.

For Arch Linux host prerequisites and the Netavark/nftables admission check,
see [`docs/platforms/arch-linux.md`](../../docs/platforms/arch-linux.md).
