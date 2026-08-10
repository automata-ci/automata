# Protobuf code generation

`proto/automata/runner/v1/runner.proto` is the authoritative wire schema.
Production builds consume the checked-in private prost DTO and therefore need
neither a build script nor `protoc`.

The verifier uses `protox` 0.9.1 and `prost-build` 0.14.4. Their complete
dependency graph is pinned in `tools/codegen.Cargo.lock`. The small tool
manifest and source are templates rather than a workspace package: the script
copies them into `target/agent-scratch`, builds there with `--locked`, and
removes the scratch directory on exit. `TMPDIR` and `CARGO_TARGET_DIR` also
remain below that repository-local scratch directory. The script uses the
repository's shared canonical-target guard, rejects symlinks in its target and
scratch ancestry, and creates an unpredictable private directory with
`mktemp`. `AUTOMATA_PROTOBUF_CODEGEN_SCRATCH_DIR` may select another exact,
non-symlinked child below the repository target for containment testing.

From the repository root, verify that the generated DTO is byte-for-byte
current:

```console
crates/automata-ci-protocol-protobuf/tools/protobuf-codegen.sh verify
```

CI can additionally apply the repository's `cargo-deny` policy to the
isolated, locked generator dependency graph (this requires `cargo-deny`):

```console
crates/automata-ci-protocol-protobuf/tools/protobuf-codegen.sh audit
```

After intentionally changing the schema, regenerate it:

```console
crates/automata-ci-protocol-protobuf/tools/protobuf-codegen.sh regenerate
```

Then review both the schema and DTO diff, review any affected wire golden
fixtures, and update the reviewed digests in
`proto/automata/runner/v1/PROVENANCE.sha256`. Do not hand-format the generated
file. The external `codegen_contract` tests verify the schema, DTO, generator
source, manifest, lockfile and verifier digests, exact tool versions, package
name, and a fresh regeneration.

## Canonical idempotency bytes

Protobuf decoders can accept unknown fields, reordered fields, and multiple
valid encodings of the same logical message. Idempotency and operation hashes
must therefore use bytes produced by this adapter's canonical encoder after
successful decode and domain validation. They must never hash the raw accepted
frame.
