# Local runner bootstrap

`runner.local.example.json` is the checked-in Linux dogfood configuration. It
selects the content-attested Ubuntu 24.04 image and points GitHub context URLs
at a smart HTTP repository server on `automata-git.ghe.com:8088` so an
unchanged shallow checkout can be tested before it is pushed. A static web
server is insufficient because Git's dumb HTTP transport cannot honor the
workflow's `fetch-depth: 1` request. The explicit
`map_github_server_to_host_gateway` Podman option maps exactly that configured
hostname into each job sandbox; production configurations do not add a host
mapping by default. The `.ghe.com` suffix is recognized by the official
artifact client and, unlike `.localhost`, is not forced to container loopback
by the system resolver.

The checked-in document uses conventional service-owned locations under
`/var/lib/automata-runner` and `/etc/automata-runner`. Copy it to an ignored,
host-specific path when the runner account, uid, or storage layout differs;
in particular, `podman.runtime_directory` must name that account's
`/run/user/<uid>` directory.

Before starting it, provision these inputs outside temporary hierarchies:

- `/etc/automata-runner/tls/server-ca.pem` and `runner.pem`, readable but not
  group/world writable;
- `/etc/automata-runner/tls/runner-key.pem`, owned by the runner user with mode
  `0600`;
- `AUTOMATA_RUNNER_SPOOL_KEY_HEX`, exactly 64 hexadecimal characters;
- `AUTOMATA_S3_ACCESS_KEY_ID` and `AUTOMATA_S3_SECRET_ACCESS_KEY` for the
  existing RustFS `automata-dev` bucket.

Create the immutable snapshot, then serve its exact output root through the
bounded read-only CGI bridge. Both roots must already exist as canonical
absolute directories and must be disjoint; the scratch directory keeps backend
temporary state under the repository's `target` hierarchy.

The bridge must bind one exact RFC 1918 host address. A wildcard listener would
also expose the unauthenticated read endpoint on LAN, Tailscale, and any other
host address. Render and review the independent nftables guard, then apply and
audit it before starting the listener. These commands show the checked-in
development example; copy the config to a nonsymlink host-specific path when
the address differs.

```console
./scripts/dev/create-dogfood-snapshot.sh target/dogfood/source
install -d -m 0700 target/runner-local/git-http-scratch
./scripts/dev/git-bridge-firewall.sh render \
  --config deploy/dev/git-bridge-firewall.env.example
sudo ./scripts/dev/git-bridge-firewall.sh apply \
  --config deploy/dev/git-bridge-firewall.env.example
sudo ./scripts/dev/git-bridge-firewall.sh audit \
  --config deploy/dev/git-bridge-firewall.env.example
python3 scripts/dev/git-http-server.py \
  --project-root "$(realpath target/dogfood/source)" \
  --scratch-directory "$(realpath target/runner-local/git-http-scratch)" \
  --git-http-backend "$(realpath "$(git --exec-path)/git-http-backend")" \
  --listen-address 192.168.0.8 \
  --port 8088
```

The URL remains `http://HOST:PORT/OWNER/REPOSITORY`. The bridge accepts only
the smart read endpoints for `git-upload-pack`; it does not expose pushes or
arbitrary CGI paths. The server rejects wildcard, public, carrier-grade NAT,
and non-canonical addresses. Loopback and an ephemeral port are accepted only
with the explicit test-only option used by its isolated contract suite. See the
Arch host guide for the required host-gateway packet-path capture and safe
firewall removal procedure.

Inject environment secrets with the process supervisor, then run:

```console
target/x86_64-unknown-linux-musl/release/automata-runner run \
  --config crates/automata-runner/config/runner.local.example.json
```

The optional repository, workflow, and results token sources in schema v1 are
only a trusted, single-tenant bootstrap. The runner intentionally fails opaque
`JobIR` secret references closed until the control protocol supplies a
job-scoped secret and credential authority.
