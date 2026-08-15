# automata-ci-blob-s3

`automata-ci-blob-s3` implements Automata's immutable blob-storage port for
S3-compatible services. It conditionally creates objects and verifies stored
bytes by size and SHA-256; it does not use object listing or mutable object
state for coordination.

The control plane and runner compose this adapter behind `automata-ci-blob`.
PostgreSQL remains the coordination authority for the product.

- [Control-plane configuration](https://github.com/automata-ci/automata/blob/main/crates/automata-ci/README.md)
- API documentation: run `cargo doc -p automata-ci-blob-s3 --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
