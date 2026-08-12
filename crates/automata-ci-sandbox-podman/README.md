# automata-ci-sandbox-podman

`automata-ci-sandbox-podman` implements Automata's whole-job sandbox contracts
with local, rootless Podman. Commands use bounded argument lists and an
allowlisted environment; the adapter does not mount a Podman socket, forward
host credentials, or issue global prune operations.

`automata-runner` composes this adapter behind `automata-ci-execution` for the
current Linux execution path.

The adapter fails closed unless it runs in a cgroup-v2 systemd service with an
empty delegated root and the process moved into a supervisor subgroup:

```systemd
[Service]
Delegate=yes
DelegateSubgroup=supervisor
MemorySwapMax=0
```

It enables and verifies the delegated CPU, memory, and process controllers,
forces rootless Podman to use cgroupfs beneath that exact root, and requests
equal memory and memory-plus-swap limits. Before exposing a sandbox on create,
replay, or attach, it proves from `/proc` and cgroupfs that the live workload is
a descendant and that the boundary has both `memory.swap.max=0` and
`memory.swap.current=0`. Missing delegation, a different cgroup layout, or a
swappable boundary stops the owned workload and rejects the operation.

- [Runner host guide](https://github.com/automata-ci/automata/blob/main/docs/platforms/arch-linux.md)
- API documentation: run `cargo doc -p automata-ci-sandbox-podman --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
