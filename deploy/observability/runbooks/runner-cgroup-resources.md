# Runner aggregate cgroup resources

These metrics describe the runner-owned delegated cgroup-v2 parent and all of
its sandbox descendants. They are deliberately aggregate; they cannot identify
one attempt, container, or block device.

Before enabling runner metrics in production, host admission must verify that
the stable delegated parent exposes readable `cpu.stat`, `memory.current`,
`memory.peak`, `memory.events`, `pids.current`, and `io.stat` to the runner
service identity. Kernels or delegation policies that omit any file are not a
supported aggregate-resource telemetry target: execution may remain healthy,
but the resource sampler will deliberately remain unhealthy rather than
publish a partial snapshot. Repeat this preflight after kernel, systemd, or
cgroup-policy changes.

1. Check `automata_ci_runner_cgroup_snapshot_healthy` and the age of
   `automata_ci_runner_cgroup_snapshot_last_success_timestamp_seconds` before
   trusting resource values. The ten-second sampler keeps the last good
   snapshot after an error or one-second timeout. A zero timestamp means it has
   never completed a successful sample in this process.
2. For an unhealthy or stale sampler, verify that the configured delegated
   cgroup exists beneath `/sys/fs/cgroup`, is cgroup v2, and exposes readable
   `cpu.stat`, `memory.current`, `memory.peak`, `memory.events`, `pids.current`,
   and `io.stat`. Capture permissions, mount state, and the bounded refresh
   outcome counters without copying cgroup paths into metric labels.
3. For sustained throttling, compare the five-minute throttled-period ratio
   with `rate(automata_ci_runner_cgroup_cpu_usage_seconds_total[5m])`, active
   slots, node CPU pressure, and the runner's aggregate CPU limit. The alert
   requires more than 25% throttled periods, an active-period floor, and a
   fifteen-minute duration; a high ratio on an idle cgroup is filtered out.
4. For an OOM kill, correlate the ten-minute increase with current/peak memory,
   active jobs, sandbox limits, and kernel/runtime evidence. The sampler first
   establishes a baseline, so it does not claim OOM events that predate the
   runner process. Preserve workload-versus-platform evidence before changing
   limits.
5. Inspect aggregate read/write byte and operation rates plus current PID count
   for leaks or saturation. Use runtime and node tools for attribution; never
   add attempt, device, path, image, or cgroup labels to these families.
6. Restore cgroup delegation, capacity, or workload limits while preserving
   journal and spool state. Do not delete durable runner state or sandboxes only
   to make a resource alert disappear.

The stable delegated-parent counters remain cumulative when child cgroups are
deleted. Automata converts their deltas into process-local monotonic counters;
a raw decrease indicates unexpected parent reset or recreation and starts a new
raw epoch. Prometheus `rate()` and `increase()` handle runner-process resets;
do not sum raw counter values across time.
