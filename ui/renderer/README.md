# Embedded SSR build

Automata compiles the Vite server bundle into a WASI Preview 2 component and
embeds that component with the browser JavaScript and CSS in the Rust binary.
Generated code and binary assets are build outputs under `target/ui-renderer`;
they are not committed to Git.

The component boundary is deliberately narrow:

```wit
package automata:ui@1.0.0;

world renderer {
    export render: func(request: string) -> string;
}
```

The authoritative WIT file is
`../../crates/automata-ci-ui-renderer/wit/renderer.wit`. The host gives the
guest no inherited filesystem, sockets, environment, arguments, or standard
streams. Each request receives a fresh store and component instance with
bounded input, output, memory, tables, instances, host resources, fuel,
concurrency, and wall time.

## Build

Run the locked profile launcher before a Cargo build from a fresh checkout or
after changing UI source:

```console
./scripts/ui/reproduce-renderer-in-profile.sh
cargo build --workspace --locked
```

The launcher uses the digest-pinned Ubuntu 24.04 build profile containing Rust
1.97.1, Node.js 24.19.0, `wasm-rquickjs-cli` 0.4.1,
`cargo-cyclonedx` 0.5.9, Clang/libclang 18.1.3, and WASI SDK 24.0. Outside that
profile it starts the exact profile image with Docker or Podman; it never falls
back to an ambient toolchain.

The build runs `npm ci`, builds the client and SSR Vite targets, generates the
wasm-rquickjs wrapper, replaces its broad manifest with the reviewed
`wrapper.Cargo.toml` and `wrapper.Cargo.lock`, and compiles only the `p2` and
`encoding` features. The vendored `rquickjs-macro` patch removes upstream
clean-build nondeterminism. Rust and C paths are remapped, incremental builds
are disabled, and `SOURCE_DATE_EPOCH` is fixed.

The resulting directory contains:

```text
target/ui-renderer/
├── assets/
│   ├── client-<sha256>.js
│   ├── renderer-<sha256>.wasm
│   └── styles-<sha256>.css
├── manifest.json
├── provenance.toml
└── renderer.cdx.json
```

`manifest.json` maps the content-addressed build files to their public Vite
paths. Cargo's renderer build script validates the manifest, filenames, file
types, sizes, digests, and exact asset set, then writes Rust bindings into
Cargo's `OUT_DIR`. `provenance.toml` and the CycloneDX document are release
evidence generated alongside the assets; there is no separate checksum
inventory.

Verify existing output without rebuilding it with:

```console
./scripts/ui/verify-renderer-build.sh
```

Release automation stages the three assets and `manifest.json` into the
published `automata-ci-ui-renderer` crate. That staging directory is ignored
and is never source-controlled. Installed Automata binaries do not require
Node.js or a JavaScript sidecar.
