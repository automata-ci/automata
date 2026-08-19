# automata-ci-windows-broker-hcs

Privileged fixed-endpoint HCS/container-engine adapter for the Automata Windows
broker. It implements the broker core's host-compute port and accepts no
caller-selected engine endpoint or isolation mode. The runner does not link
this crate.

For exec and copy, the adapter's only in-container engine command is the
immutable guest executable with `stdio-once`. It sends one bounded,
length-prefixed guest-protocol frame over standard input and accepts one
bounded response over standard output. Workload argv and environment never
enter the engine exec document. The guest starts each workload inside a nested
Windows Job Object with the admitted per-command process ceiling and kills the
whole process tree on timeout; file transfer uses the same guest protocol and
does not invoke an archive tool.
