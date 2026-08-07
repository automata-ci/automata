# `automata` control plane

`automata server` (also available as `automata serve`) runs one horizontally
scalable control-plane replica. The same binary also contains the operator CLI
and React/Vite server-side-rendered interface; deployment does not require an
application sidecar or a JavaScript runtime.

Each replica binds three deliberately separate sockets before starting:

- `--listen` serves the human API, health endpoints, and SSR interface.
- `--runner-listen` serves the runner protocol over direct mutual TLS and
  HTTP/2 only. It must not receive client identities through reverse-proxy
  headers. A proxy-terminated runner transport would be a different adapter
  with its own explicit trust contract.
- `--results-listen` serves the GitHub Actions Results compatibility protocol.
  Its `--results-public-url` is placed in a short-lived credential bound to the
  exact run, job, attempt, and fencing token. Production URLs must use HTTPS;
  TLS may terminate at a trusted proxy in front of this dedicated listener.

The server requires PostgreSQL and one S3-compatible immutable object
namespace. Embedded PostgreSQL migrations and an immutable put/read object
probe must succeed before `/readyz` returns HTTP 200. Both checks continue at
the configured readiness interval; `/healthz` only reports process/build
health and is intentionally not a readiness substitute.

## Credential references

Credential and PEM values are not accepted directly in command arguments.
Every corresponding option takes one of these references:

```text
env:ENVIRONMENT_VARIABLE
file:/mounted/secret/path
```

Examples include `--database-url-source`, `--s3-access-key-source`,
`--s3-secret-key-source`, `--runner-client-ca-source`,
`--runner-server-cert-source`, `--runner-server-key-source`, and
`--results-signing-key-source`. References are redacted from debug and startup
errors, and loaded bytes have context-specific hard ceilings. The runner trust
bundle must contain one or more PEM
certificates; the server identity must contain a PEM certificate chain and
exactly one supported PEM private key. TLS 1.3 and direct client-certificate
validation are mandatory.

For local RustFS, explicitly opt into loopback HTTP:

```sh
automata server \
  --results-public-url https://results.example.com/ \
  --s3-endpoint http://127.0.0.1:9000/ \
  --s3-allow-loopback-http \
  --s3-bucket automata-dev \
  --s3-prefix automata/v1 \
  --database-url-source file:target/local-secrets/database-url \
  --s3-access-key-source file:target/local-secrets/s3-access-key \
  --s3-secret-key-source file:target/local-secrets/s3-secret-key \
  --runner-client-ca-source file:target/local-secrets/runner-ca.pem \
  --runner-server-cert-source file:target/local-secrets/server-chain.pem \
  --runner-server-key-source file:target/local-secrets/server-key.pem
```

Plain HTTP object-store endpoints anywhere other than a loopback host are
rejected even when the development flag is present.

The server and every runner in an installation must use the same bucket and
logical key prefix. The server publishes immutable `JobIR`, workflow event,
log, result, and artifact objects there; runners verify those exact keys and
also publish immutable action bundles. A differing prefix fails closed as a
missing object and is never searched or guessed.

For a local rootless-Podman job, loopback belongs to the sandbox and cannot be
used for Results. The explicit development mode therefore requires an exact
private host bind and an exact asserted public host; wildcard binds are
rejected:

```sh
automata server \
  --results-listen 192.168.0.8:8081 \
  --results-public-url http://host.containers.internal:8081/ \
  --results-allow-development-http \
  --results-trusted-private-host host.containers.internal \
  --results-signing-key-source file:target/local-secrets/results-hmac.key \
  # ...the PostgreSQL, S3, and mTLS references above...
```

This private HTTP mode is for a firewall-constrained local bridge only. It is
not a production TLS substitute.

## Dependency-free image smoke mode

`automata preview --listen 127.0.0.1:8080` serves only build health, readiness,
embedded assets, and the React SSR interface. It is the explicit command used
to exercise the fully static binary inside a `FROM scratch` image. It never
starts runner control, scheduling, workflow admission, Results, PostgreSQL, or
S3 adapters; production `automata server` never falls back to this mode when a
credential or dependency is missing.
