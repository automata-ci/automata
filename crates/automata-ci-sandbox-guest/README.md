# Automata sandbox guest

`automata-ci-sandbox-guest` provides the bounded, versioned command transport
used inside Automata Kubernetes job sandboxes. Its executable is packaged in a
dedicated guest image and copied into each workload Pod by an init container;
the library exposes the same framing and validation contract to the Kubernetes
sandbox adapter.

The guest keeps command arguments, environment values, and file contents out
of Kubernetes Pod specifications and exec request URLs. Operators must build
and publish the image from the reviewed repository source, then configure the
runner with an architecture-compatible digest-pinned image reference as
described by the
[`automata-ci-sandbox-kubernetes` contract](../automata-ci-sandbox-kubernetes/README.md#guest-image-contract).
