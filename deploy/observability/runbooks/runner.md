# Runner control and execution

1. Check process `up`, `automata_ci_runner_ready`,
   `automata_ci_runner_session_connected`, and last control-success age.
   `automata_ci_runner_journal_session_present` is only resumability, not a
   live connection.
2. Inspect handshake/reconnect outcomes, physical control retries, retry
   backoffs, typed remote errors, and server clock offset.
3. Check `automata_ci_runner_slot_snapshot_conserved`, then compare
   `automata_ci_runner_slots_over_capacity` with the durable journal slot count.
   Slot states sum to the greater of configured and durable journal slots; do
   not delete journal state merely to silence an over-capacity warning.
4. For active work, check heartbeat/renewal progress and lease expiry before
   investigating executor phases.
5. Distinguish infrastructure executor failures from user job conclusions.
   Normal job failures must not page the runner platform team.
6. Inspect sandbox/Podman typed stages, host or container-runtime OOM signals,
   output truncation, and cleanup or orphan recovery. Metric labels never
   contain argv, paths, images, or output.
