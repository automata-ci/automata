# Integration tests: Platform, provider, and topology adapters

Provide disposable execution environments without letting test infrastructure
advertise a product capability early. Read the
[integration-test hub](github-actions-parity-11-integration-tests.md) first for
the evidence model, ownership boundary, security rules, and team schedule.

**Package IDs:** IT-07, IT-09, IT-10, IT-11, IT-12.

The packages are split by environment so Windows acceptance does not wait for
Kubernetes or macOS, and the chaos gate does not wait for Windows breadth.

## Work packages

### IT-07 — Disposable Linux product adapter

**Owner:** P with X review. **Size:** L. **Dependencies:** IT-01, FND-02.

**Primary scope:** make the current manual Linux deployment repeatable,
observable, and safely disposable before the corpus becomes gating.

Tasks:

- [ ] Define the common platform-adapter contract for provision, verify,
  execute, observe, collect, fault, and destroy operations.
- [ ] Verify root-owned trust paths, the host-tool allowlist, cgroup v2/systemd,
  subordinate IDs, rootless Podman, and dedicated per-runner `tmpfs,noswap`
  storage before executing third-party code.
- [ ] Record exact OS build, architecture, provider version, runner identity,
  resource allocation, image/profile, network, storage, and isolation mode.
- [ ] Keep each attempt in a dedicated identity, work root, storage prefix,
  network boundary, port set, and metrics label set.
- [ ] Observe through versioned product/provider APIs; never read Automata's
  database as test truth.
- [ ] Prove cleanup after success, failure, cancellation, and process loss.

Acceptance:

- [ ] The adapter runs one shipped-process Chalk smoke and proves identity,
  storage, network, process, and workspace cleanup.
- [ ] A stale endpoint, runner, credential, mount, or workspace prevents a
  passing result.

### IT-09 — Windows native adapter

**Owner:** P with R and X review. **Size:** L. **Dependencies:** IT-01, IT-07,
FND-02, WIN-03, CACHE-03.

**Primary scope:** hosted/dedicated Windows execution through the shipped
runner process without implying VM/container isolation.

Tasks:

- [ ] Implement the common adapter contract on Windows with exact OS,
  PowerShell, runner, provider, profile, and filesystem evidence.
- [ ] Launch the shipped `automata-runner run` process and bind its identity to
  the accepted release bundle.
- [ ] Record the inherited host identity/network/filesystem and Job Object
  process/resource-containment boundary explicitly.
- [ ] Run only scenarios admitted by the Windows product capability set; fail
  rather than falling back to Linux or silently omitting `uses:` steps.
- [ ] Prove Job Object descendant cleanup, provider restart reconciliation,
  workspace/scratch removal, and no stale generation reuse.
- [ ] Run cross-OS cache evidence only after `CACHE-03` accepts its archive
  semantics.

Acceptance:

- [ ] One shipped-process Windows smoke passes with exact logs/results and
  cleanup evidence.
- [ ] The adapter cannot advertise Windows support before `WIN-03` and
  `CACHE-03` accept the gate fixture.

### IT-10 — Kubernetes provider adapter

**Owner:** P with X review. **Size:** L. **Dependencies:** IT-01, IT-07,
FND-02, PROV-03.

**Primary scope:** a disposable production-like cluster boundary for the
already composed Kubernetes provider.

Tasks:

- [ ] Provision a dedicated namespace, service identity, storage prefix,
  network policy, and bounded resource quota for each run.
- [ ] Prove RBAC, admission, RuntimeClass, CNI, node-traffic exception,
  ephemeral-storage/GPU/process enforcement, and service-account-token policy.
- [ ] Exercise create, inspect, attach, exec, copy, destroy, uncertain create,
  runner loss, and provider restart through product APIs.
- [ ] Verify Pods cannot receive the ambient runner's Kubernetes credential.
- [ ] Delete every namespace-owned resource and distinguish cluster cleanup
  failure from Automata cleanup failure.

Acceptance:

- [ ] One admitted Kubernetes smoke passes with exact resource and cleanup
  evidence against a real cluster.
- [ ] The adapter cannot advertise Kubernetes readiness before `PROV-03`.

### IT-11 — macOS ARM64 native adapter

**Owner:** P with R and X review. **Size:** L. **Dependencies:** IT-01, IT-07,
FND-02, PLAT-02.

**Primary scope:** the accepted Apple Silicon macOS 15+ Bash/sh slice; actions,
containers, Intel, signing jobs, and Xcode profiles stay outside this package.

Tasks:

- [ ] Implement the common adapter contract on a disposable/dedicated Apple
  Silicon macOS 15+ host.
- [ ] Record exact OS/build, architecture, runner, shell, optional Python/pwsh,
  identity, filesystem, network, and cleanup boundaries.
- [ ] Run only the admitted native `run:` smoke without action/container
  substitution.
- [ ] Prove process-tree termination, workspace cleanup, restart handling, and
  no persistent keychain/developer credential access.

Acceptance:

- [ ] One ARM64 native smoke passes through shipped processes and cleans all
  owned state.
- [ ] Intel, actions, containers, signing, and Xcode are still rejected or
  represented by later product packages.

### IT-12 — Multi-replica and fault topology adapter

**Owner:** P with S, C, and X review. **Size:** XL. **Dependencies:** IT-01,
IT-07, FND-02, FLT-04.

**Primary scope:** independently controlled replicas, partitions, clocks,
resource pressure, and cleanup instrumentation consumed by `GATE-05`.

Tasks:

- [ ] Provision multiple control, materialization, scheduler, projector,
  Results, and fleet-controller replicas with unique identities and metrics.
- [ ] Add bounded controls to stop, restart, partition, delay, corrupt, and
  restore each external boundary independently.
- [ ] Record exact topology, fault timing, operation identity, durable state
  transition, observed invariant, and recovery time.
- [ ] Keep fault controls outside product trust and credential paths; a test
  fault cannot forge successful evidence.
- [ ] Exercise only the exact current runner protocol; mixed-version operation
  is unsupported.
- [ ] Tear down every replica, network rule, volume, namespace, credential, and
  retained process even when the test driver crashes.

Acceptance:

- [ ] The adapter can inject each `GATE-05` fault without replacing real
  product components with in-memory fakes.
- [ ] A missing cleanup or unknown durable outcome is a failed test, not a
  quarantinable environmental difference.

---

[Previous: Corpus qualification](github-actions-parity-11b-integration-corpus.md) · [Integration-test hub](github-actions-parity-11-integration-tests.md) · [Parent execution plan](../github-actions-parity-execution-plan.md)
