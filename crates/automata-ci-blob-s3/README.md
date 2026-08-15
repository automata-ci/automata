# automata-ci-blob-s3

`automata-ci-blob-s3` implements Automata's immutable blob-storage port for
S3-compatible services. It conditionally creates objects and verifies stored
bytes by size and SHA-256; it does not use object listing or mutable object
state for coordination.

The control plane and runner compose this adapter behind `automata-ci-blob`.
PostgreSQL remains the coordination authority for the product.

HTTPS clients use one closed trust policy. `S3TlsTrust::web_pki()` selects the
platform Web PKI store. `S3TlsTrust::private_ca(...)` accepts exactly one valid
X.509 CA certificate and installs it into an otherwise empty trust store; it
never merges or retries with Web PKI roots. Private-CA input is capped at 1 MiB
and is incompatible with plaintext endpoints. Its bytes must be the canonical
RFC 7468 encoding with 64-column Base64, LF line endings, one terminal LF, and
no preamble or trailing bytes. A present KeyUsage must include `keyCertSign`.

`S3BlobStoreConfig::connect` is the sole public construction boundary, so the
SDK client, validated endpoint/namespace, credentials, and exact trust policy
cannot be rebound independently. Connected-store debug output is one fixed
redacted value and exposes none of that bound state. The resulting store's production
`ensure_bucket` operation performs `HeadBucket`, creates only after an exact
not-found response, and requires a final successful `HeadBucket` after creation
or a creation conflict. Creation omits `LocationConstraint` only for
`us-east-1` and sends every other validated region exactly. The complete
sequence shares the validated operation deadline and never treats a conflict
alone as success.

- [Control-plane configuration](https://github.com/automata-ci/automata/blob/main/crates/automata-ci/README.md)
- API documentation: run `cargo doc -p automata-ci-blob-s3 --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
