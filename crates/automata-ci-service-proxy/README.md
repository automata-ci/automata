# automata-ci-service-proxy

`automata-ci-service-proxy` is Automata's Linux-only, credential-free network
helper. Its current `serve-v1` mode is the namespace-local TCP and UDP port
proxy for job service containers: the sandbox launches it inside the job
network namespace with a closed mapping list, loopback listeners, and validated
non-loopback IPv4 service addresses.

The separate `serve-results-v1` mode is not a generic mapping interface. It
accepts exactly five canonical private-IPv4 facts: the proxy address, exact
`/29` front CIDR, sole job source address, non-overlapping `/23`-or-wider
transit CIDR, and numeric Results target. The front gateway, proxy, and job are
fixed at host offsets 1, 2, and 3. The Results target must be a usable transit
host other than its fixed first-host gateway. The helper binds only the front
proxy address on TCP port 8081, accepts only the exact job source, and connects
only to the supplied target on TCP port 8081. UDP, dynamic listeners, public or
loopback addresses, partially public CIDRs, alternate address layouts,
overlapping networks, additional targets, and additional arguments are
rejected. Its exact readiness line is
`{"version":1,"mode":"results-v1","port":8081}`.

The process has fixed listener, TCP-session, UDP-association, datagram, and
per-event work ceilings. TCP relays preserve normal half-close behavior. After
either peer closes its write half, that EOF is propagated only to the opposite
write half; the other direction remains available for delayed, streaming, or
one-way traffic. Results sessions use one shared last-activity deadline that is
refreshed by traffic in either direction. Once the upstream response half has
closed, a still-open request half also has a shorter inactivity drain, refreshed
by continued uploads; a client request half-close does not activate that drain.
UDP associations expire after inactivity. Startup writes one compact ordered
status line to standard output; subsequent diagnostics are sanitized error
codes and never reflect command input or proxied bytes.

Results mode has an Engine-enforced listen backlog of 16, at most 32 concurrent
sessions, a five-second target-connect deadline, a five-minute idle deadline,
a five-second inactive request drain after response half-close, and directional
half-close propagation. Streaming is body-neutral and bounded by
connection/session limits rather than buffering request or response bodies; a
genuinely inactive session is still reaped by the applicable shared deadline.

This binary is an internal image helper, not a general-purpose host proxy or a
stable operator-facing CLI. The sole current image capability is
`io.automata.service-proxy.protocol-version=2`, which binds both command modes
above; protocol 1 images predate the Results mode and are rejected. It requires
Linux `epoll`, assumes the sandbox has already established its network and
process isolation, and must be distributed as the reviewed immutable scratch
image expected by the runner profile. The image runs as `65532:65532`; callers
must keep it read-only, capability-free, mount-free, and free of environment
values or credentials.

- [Runner configuration](https://github.com/automata-ci/automata/blob/main/crates/automata-ci-runner/config/README.md)
- [Issues and support](https://github.com/automata-ci/automata/issues)
