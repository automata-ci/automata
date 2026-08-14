# Automata sandbox guest

`automata-ci-sandbox-guest` provides the bounded, versioned command transport
used inside Automata Kubernetes Pods, macOS virtual machines, and
Hyper-V-isolated Windows containers. Kubernetes packages the executable in a
dedicated guest image and copies it into each workload Pod; the macOS template
and Windows runner image bake the reviewed executable into their immutable
artifacts.

Protocol v3 keeps command arguments, environment values, and file contents out
of Kubernetes Pod specifications, exec request URLs, and Windows
container-runtime command lines. Unix guests use the persistent authenticated
socket lifecycle; Windows uses one framed request over anonymous standard
input per `docker exec`, while the host provider owns lifecycle, replay, and
recovery fencing. Protocol v1 and v2 traffic is rejected rather than migrated.

Operators must build and publish every guest-bearing image or VM template from
reviewed repository source, then configure the runner with an
architecture-compatible digest pin. The Kubernetes image contract is
described by the
[`automata-ci-sandbox-kubernetes` contract](../automata-ci-sandbox-kubernetes/README.md#guest-image-contract).
The Windows host and image acceptance requirements are in the
[Windows isolation plan](../../docs/platforms/windows.md).
