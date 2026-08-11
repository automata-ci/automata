# automata-ci-ui-renderer

`automata-ci-ui-renderer` provides Automata's isolated server-side React
renderer and immutable embedded client assets. Rendering runs inside a bounded
Wasmtime component with explicit resource policy; the crate returns rendered
HTML and asset metadata to the control-plane web layer.

The `automata preview` and `automata server` commands compose this crate. It is
not a standalone web server or frontend framework.

- [Development documentation](https://github.com/automata-ci/automata/blob/main/docs/development.md)
- API documentation: run `cargo doc -p automata-ci-ui-renderer --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
