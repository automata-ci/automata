# Embedded SSR artifacts

Automata executes the Vite server bundle as a WASI Preview 2 component. The
component and Vite client assets in `assets/` are generated, hash-addressed,
checked into Git, and embedded by `automata-ui-renderer`. Cargo never runs npm,
downloads JavaScript tooling, or generates these files implicitly.

The component boundary is deliberately narrow:

```wit
package automata:ui@1.0.0;

world renderer {
    export render: func(request: string) -> string;
}
```

The authoritative WIT file lives at
`../../crates/automata-ui-renderer/wit/renderer.wit`. The host gives the guest
no inherited filesystem, sockets, environment, arguments, stdin, stdout, or
stderr. It creates a fresh store and component instance for every request and
enforces input, output, memory, table, instance, host-resource, fuel,
concurrency, and wall-time limits.

## Regeneration

Install `wasm-rquickjs-cli` 0.4.1, `cargo-cyclonedx` 0.5.9, and Rust
1.97.1 with the `wasm32-wasip2` target, then run:

```console
scripts/ui/regenerate-renderer.sh
```

The script uses `npm ci`, builds both Vite targets, generates a temporary
wasm-rquickjs wrapper, replaces its general-purpose dependency declaration and
resolution with the reviewed `wrapper.Cargo.toml` and `wrapper.Cargo.lock`, and
builds with exactly:

```console
cargo build --locked --release --target wasm32-wasip2 \
  --no-default-features --features p2,encoding
```

The reviewed manifest exposes only the `p2` and `encoding` features and pins the
18 direct dependencies used by that profile. This prevents unused optional
crypto, SQLite, Preview 3, and git-patched packages from entering the lockfile,
SBOM, or dependency-policy audit. A narrowly vendored `rquickjs-macro` patch
uses insertion-ordered collections when emitting tokens, removing upstream
clean-build nondeterminism; its complete source tree is bound into provenance.
The large generated wrapper source is
intentionally not committed. A candidate
is generated and compared with the stable, ignored
`target/ui-renderer-wrapper/source` tree; the stable tree is replaced only when
its content changes. This keeps Cargo's path-package identity and procedural
macro output stable across no-op regenerations. Builds also use one codegen
unit, disabled incremental compilation, a fixed `SOURCE_DATE_EPOCH`, and a
repository path remap. `PROVENANCE.toml` records tool, source-bundle, manifest,
lockfile, WIT, public-path, and artifact hashes. `renderer.cdx.json` inventories the Rust
dependency graph compiled into the component and binds it to the component's
SHA-256 digest. Review both like any other executable dependency.

Verification is offline and does not rebuild anything:

```console
scripts/ui/verify-renderer-assets.sh
```

After regeneration, audit the selected wrapper graph with the repository policy:

```console
cargo deny --manifest-path target/ui-renderer-wrapper/source/Cargo.toml \
  --locked --config deny.toml check advisories bans licenses sources
```
