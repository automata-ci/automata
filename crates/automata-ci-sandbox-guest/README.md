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

The evaluation-only local Docker provider extracts this same reviewed binary
from one already-present immutable guest image and starts it as PID 1 in each
sibling job container. Its protected client is sealed into a private tmpfs
control directory and accepts requests only from the expected peer identity.
Local Docker requests are executed once: durable host state owns request and
result replay, and an ambiguous committed invocation requires destruction of
the exact sandbox before the attempt can be abandoned. The guest does not
claim that such an invocation is safe to restart.

Operators must build and publish every guest-bearing image or VM template from
reviewed repository source, then configure the runner with an
architecture-compatible digest pin. The Kubernetes image contract is
described by the
[`automata-ci-sandbox-kubernetes` contract](../automata-ci-sandbox-kubernetes/README.md#guest-image-contract).
The Windows host and image acceptance requirements are in the
[Windows isolation plan](../../docs/platforms/windows.md).
