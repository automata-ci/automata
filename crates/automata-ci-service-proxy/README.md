# automata-ci-service-proxy

`automata-ci-service-proxy` is Automata's Linux-only, namespace-local TCP and
UDP port proxy for job service containers. The sandbox launches it inside the
job network namespace with a closed `serve-v1` mapping list. It binds only
loopback listener ports and forwards them to validated non-loopback IPv4
service addresses.

The process has fixed listener, TCP-session, UDP-association, datagram, and
per-event work ceilings. TCP relays preserve normal half-close behavior. After
the upstream closes its response half, a still-open request pump receives a
bounded drain before it is reaped; a client request half-close does not truncate
a delayed or streaming upstream response. UDP associations expire after
inactivity. Startup writes one compact ordered status line to standard output;
subsequent diagnostics are sanitized error codes and never reflect command
input or proxied bytes.

This binary is an internal image helper, not a general-purpose host proxy or a
stable operator-facing CLI. It requires Linux `epoll`, assumes the sandbox has
already established its network and process isolation, and must be distributed
as the reviewed immutable helper image expected by the runner profile.

- [Static runner deployment](https://github.com/automata-ci/automata/blob/main/docs/deployment.md#bootstrap-one-static-local-runner)
- [Platform architecture](https://github.com/automata-ci/automata/blob/main/docs/platforms/arch-linux.md)
- [Issues and support](https://github.com/automata-ci/automata/issues)
