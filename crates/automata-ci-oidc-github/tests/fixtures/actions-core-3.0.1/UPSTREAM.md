The `oidc-utils.js` source is copied from the published
`@actions/core` 3.0.1 package (`sha512-a6d/Nwahm9fliVGRhdhofo40HjHQasUPusmc7vBfyky+7Z+P2A1J68zyFVaNcEclc/Se+eO595oAr5nwEIoIUA==`).
It is covered by the neighboring upstream `LICENSE.md`. The repository copy adds one final
newline; the Rust fixture strips exactly that byte and pins the resulting
upstream SHA-256 before executing the module. Its two upstream template-literal
lines intentionally retain trailing spaces and are exempted locally from Git's
blank-at-EOL check.

The neighboring `core.js`, HTTP client, and module loader files are minimal
offline test doubles. They preserve the public calls made by that exact OIDC
client module without vendoring unrelated toolkit functionality.
