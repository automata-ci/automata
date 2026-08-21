# automata-ci-windows-broker-core

Pure Windows broker admission contracts and policy evaluation. This crate owns
canonical admission requests, host-input evidence, promotion/trust validation,
capability derivation, and the synthetic-probe port. It performs no filesystem
mutation, custody, state persistence, service composition, or host-compute I/O.

`automata-ci-windows-broker` composes these policies into the privileged
application service and supplies repository and custody adapters. Runner-side
code depends only on the narrow broker protocol, never on either service crate.
