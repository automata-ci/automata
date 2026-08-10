# automata-ci-ui-renderer

`automata-ci-ui-renderer` provides Automata's isolated server-side React
renderer and immutable embedded client assets. Rendering runs inside a bounded
Wasmtime component with explicit resource policy; the crate returns rendered
HTML and asset metadata to the control-plane web layer.

The `automata preview` and `automata server` commands compose this crate. It is
not a standalone web server or frontend framework.

Automata is pre-1.0 and not production-ready. This internal UI boundary and its
generated asset contract may change between releases.

- [Development documentation](https://github.com/automata-ci/automata/blob/main/docs/development.md)
- [API documentation](https://docs.rs/automata-ci-ui-renderer)
- [Issues and support](https://github.com/automata-ci/automata/issues)
