# Process resource pressure

1. Check `automata_ci_metrics_process_snapshot_healthy` and
   `automata_ci_metrics_process_snapshot_last_success_timestamp_seconds` before
   trusting the cached `process_*` gauges. The Linux sampler runs off the scrape
   path and preserves the last good snapshot after an error.
2. Compare `process_open_fds` with `process_max_fds`, then break descriptors
   down by socket, regular file, pipe, and anonymous inode using host tools.
   Preserve evidence before restarting the process.
3. Correlate `process_threads`, `process_resident_memory_bytes`,
   `rate(process_cpu_seconds_total[5m])`, and `process_virtual_memory_bytes`
   with node-exporter and container-runtime metrics. Automata's process
   families are not host or cgroup totals. On runners, use
   [`runner-cgroup-resources.md`](runner-cgroup-resources.md) for the separate
   aggregate sandbox boundary.
4. Check connection pools, in-flight operations, stuck scrapes, retry churn,
   and recent deployment changes before raising an operating-system limit.
5. Restore headroom or remove the leak while preserving durable runner journal,
   spool, command, and artifact state. Do not delete durable data to make a
   resource alert disappear.
