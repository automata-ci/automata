# automata-ci-windows-broker-protocol

Narrow runner-to-broker authorization boundary for Windows Hyper-V sandbox
creation. It exposes only bounded stable request fields and a sanitized client
result. Grant verification, persistence, watchdogs, and host-compute access are
deliberately absent.
