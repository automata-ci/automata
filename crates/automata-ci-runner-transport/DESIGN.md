# Runner control transport boundary

This library owns only the replica-neutral network/session framing boundary for
`automata.runner.v1`. It has no direct product-composition or SQL dependency;
the `automata` binary composes it through the application and machine-identity
ports described below.

- The server accepts a pre-bound, dedicated TCP listener and terminates mTLS
  itself with rustls. Only HTTP/2 and the exact `application/protobuf` media
  type are accepted. The complete peer certificate chain from rustls is passed
  to `automata_ci_auth::machine::MachineIdentityVerifier` on every request.
- `POST /automata.runner.v1.RunnerControl/Handshake` accepts only `RunnerHello`;
  `POST /automata.runner.v1.RunnerControl/Sync` accepts only post-handshake
  runner frames. The application handler receives authenticated identity,
  validated domain data, and canonical protobuf bytes on every call; it must
  independently map/fence the runner and session against shared durable state.
- Bodies, headers, connections, streams, handler calls, long polls, and client
  responses are bounded. Streaming collection enforces limits before protobuf
  decode. Chunked HTTP/1 requests cannot reach these HTTP/2-only routes.
- The client sends deterministic canonical request bytes and retains the same
  operation identity and bytes across transport retries. Semantic 4xx responses
  are never classified as retryable.
- TLS 1.3 is the only protocol version. There is no downgrade or compatibility
  policy surface.

An ordinary reverse proxy cannot terminate runner mTLS for this boundary:
forwarded certificate headers are untrusted request data and are deliberately
ignored. A future proxy integration would require a separate authenticated
transport adapter with cryptographic channel binding and a reviewed trust
contract; this crate does not provide one.

The listener uses hyper's HTTP/2 connection API directly after tokio-rustls,
rather than an axum application listener, so the accepted rustls stream remains
the sole source of peer-certificate evidence and HTTP/1 cannot be enabled by
unrelated UI routing. The outbound adapter likewise uses hyper-rustls directly
to keep roots, client identity, ALPN selection, retry classification, and byte
ceilings explicit.

## Reviewed dependency surface

The intended pinned transport stack is rustls 0.23.43 (`ring`, `std`, no default
features), tokio-rustls 0.26.4 (`ring`, no default features), hyper 1.11.0
(`client`, `http2`, `server`, no default features), hyper-util 0.1.20
(`client`, `client-legacy`, `http2`, `server`, `service`, `tokio`, no default
features), http-body-util 0.1.4, and hyper-rustls 0.27.9 (`http2`, `ring`, no
default features), plus tower-service 0.3.3 for the connector's
post-handshake ALPN guard. No native-tls or OpenSSL feature is enabled.
