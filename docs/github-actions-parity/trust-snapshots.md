# Trust snapshots and authority reduction

This document defines the Wave 1 `AUTH-02` contract implemented by Automata.
It is the single provider-neutral decision record carried from authenticated
event admission to every runtime authority consumer. Event packages remain
responsible for publishing authenticated facts for their event families;
`AUTH-02` does not claim that an event ingress path exists when its owning EVT
package has not shipped it.

## Security objective

One immutable trust decision is derived before JobIR or credentials exist. The
decision is then replayed, never guessed again, by the token, secret, cache,
environment, OIDC, output, and Results boundaries.

The contract has five non-negotiable properties:

1. Input is typed, authenticated, bounded evidence, not raw event JSON or JSON
   pointers.
2. The policy and its result are versioned, canonical, digest-bound, and stored
   at the logical-run origin.
3. Fork and automation reductions happen before JobIR projection and token
   minting.
4. Reruns preserve the original run's authority byte for byte. The new
   triggering actor is audit information and cannot upgrade authority.
5. Missing, contradictory, noncanonical, or invalid transitive evidence fails
   closed.

This layer supplies ceilings and eligibility, not final grants. For example,
`Eligible` OIDC authority still requires exact `id-token: write` permission and
the normal lease/fence/session proof.

## Versioned wire contract

The current contract is:

| Item | Value |
| --- | --- |
| Trust-policy schema | `1` |
| Trust-policy revision | `1` |
| Trust-snapshot schema | `1` |
| Media type | `application/vnd.automata.workflow-trust-snapshot.v1+json` |
| Maximum canonical snapshot | 32,768 bytes |
| Policy digest domain | `automata.workflow-trust-policy.v1` plus a NUL byte |
| Snapshot digest domain | `automata.workflow-trust-snapshot.v1` plus a NUL byte |
| Fork-write policy | `deny` |
| Repository-dispatch recursion | `require_external_origin` |

Both digests are SHA-256 over the domain separator followed by canonical JSON.
Canonical decoding rejects unknown fields, unsupported schemas, malformed or
oversized text, alternate encodings, stale derived decisions, and digest
mismatches. This makes the snapshot safe to compare byte for byte and prevents
a decoder from silently accepting a different policy decision.

## Evidence model

The snapshot keeps security dimensions separate so one display field cannot
stand in for another:

| Dimension | Sealed evidence |
| --- | --- |
| Origin | provider webhook, workflow dispatch, schedule, workflow run, or rerun |
| Event | push, pull request, pull-request target, merge group, repository dispatch, workflow dispatch, schedule, or workflow run |
| Event activity | bounded closed activity when the event defines one |
| Actors | original authority actor, current triggering actor, and distinct source actor |
| Actor identity | stable provider ID, actor kind, and automation classification |
| Repositories | independent source and target stable repository IDs and owner IDs |
| References | independent source, target, and exact execution refs |
| Revisions | independent source, target, and exact execution revisions |
| Relationship | authenticated fork boolean, checked against repository identity |
| Transition | explicit privileged/base-context transition marker |
| Transitivity | upstream snapshot digest, source classification, completeness, and depth |
| Recursion | suppressed, external, explicitly allowed, or unknown token origin |

Repository and owner IDs are provider identities, not mutable repository names
or owner logins. Manual dispatch reads them from the pinned provider manifest.
At run construction, the snapshot target repository, execution ref, and
lowercase execution revision must exactly match the admitted origin.

Every reference, revision, activity, and identity is bounded and rejects empty,
padded, control-bearing, or oversized values. A fork assertion must agree with
source and target repository identity. Dependabot cannot simultaneously be a
fork classification. Upstream evidence is permitted only for merge-group and
workflow-run events and has a maximum chain depth of three.

## Derivation flow

```text
authenticated provider/manual/schedule facts
                  |
                  v
        typed TrustEvidence validation
                  |
                  v
        pure versioned TrustPolicy
                  |
                  v
 canonical TrustSnapshot + policy/snapshot digests
                  |
                  v
 immutable logical-run persistence (PostgreSQL 0029/0030)
                  |
                  v
 activation revalidation + exact JobIR/protobuf propagation
                  |
                  v
 token | secret | cache | environment | OIDC | output | Results
```

No downstream consumer reopens webhook JSON, infers actor authority from a
login, or independently classifies a fork. JobIR schema 1 carries the exact
canonical snapshot bytes and SHA-256 digest. The runner protobuf uses fields 16
and 17 for those values.

## Event completeness rules

Evidence that does not meet its event rule remains `incomplete`; it is not
filled from mutable repository state.

| Event | Complete evidence requirement |
| --- | --- |
| Push | full actor/repository/ref/revision tuple, non-fork relationship, and provider-suppressed token recursion |
| Pull request | full tuple plus the distinct source actor; source and target stay independent |
| Pull-request target | pull-request evidence plus an explicit privileged-transition marker; source restrictions survive base-context execution |
| Merge group | full tuple plus complete upstream evidence with depth 1-3 |
| Repository dispatch | full tuple and authenticated external token origin, unless a pinned future policy explicitly permits recursion |
| Workflow dispatch | full tuple, authenticated caller, stable manifest repository/owner IDs, and non-fork relationship |
| Schedule | full tuple, scheduler identity, pinned repository evidence, and non-fork relationship |
| Workflow run | full tuple plus complete upstream snapshot digest, source class, and depth 1-3 |
| Rerun | no re-derivation is allowed; the source run's exact canonical bytes and digest are copied |

The generalized EVT registry can describe event families before their ingress
implementation lands. The trust policy covers those closed event forms, but an
unpublished ingress is not executable merely because it appears in this table.

## Source classification

Classification occurs only after completeness and consistency checks:

- `same_repository`: complete, non-fork evidence with no restricted automation
  source.
- `fork`: complete evidence whose authenticated source repository differs from
  the target repository.
- `dependabot`: complete same-repository evidence whose source authority is
  Dependabot.
- `automation`: complete evidence from other restricted provider automation.
- `incomplete`: one or more event-required dimensions are absent or transitive
  evidence cannot authorize the event.

A complete upstream workflow-run or merge-group snapshot propagates its source
classification. Chaining never launders a fork or automation run into
same-repository authority.

## Authority truth table

The following is the canonical multidimensional result. `Requested` means the
already-resolved permission mapping may pass through; it never means provider
defaults may be guessed.

| Source class | Repository permissions | Normal secrets | Cache | Protected environment | OIDC | Outputs | Results |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Same repository | Requested | Eligible | Read/write | Eligible | Eligible | Standard | Standard |
| Fork, current policy | Read-only | Denied | Restore-only | Denied | Denied | Untrusted | Untrusted |
| Fork, explicit future fork-write policy | Requested | Denied | Restore-only | Denied | Denied | Untrusted | Untrusted |
| Dependabot | Read-only | Denied | Restore-only | Denied | Denied | Untrusted | Untrusted |
| Other restricted automation | Read-only | Denied | Restore-only | Denied | Denied | Untrusted | Untrusted |
| Incomplete | Deny all | Denied | Denied | Denied | Denied | Untrusted | Denied |

Fork-write permission, if explicitly enabled by a future pinned policy, changes
only the repository-permission ceiling. It never restores normal secrets,
write-capable cache, protected environments, OIDC, trusted outputs, or standard
Results authority. Dependabot and other restricted automation remain read-only
regardless of the fork-write setting.

## Persistence and replay

Migration `0029_event_trust_control_contracts.sql` introduces the generalized
event/trust control lineage used by this stack. Migration
`0030_workflow_run_trust_snapshots.sql` stores one canonical snapshot for each
logical run, including media type, schema and policy revisions, policy digest,
snapshot digest, and canonical bytes. Database triggers reject update, delete,
and truncate operations on the trust ledger.

Logical admission includes the snapshot digest in its deterministic request
identity. PostgreSQL replay accepts an existing row only when every persisted
field is identical. Concurrent insert races re-read and compare the winning
row; a different snapshot, policy, digest, media type, or byte sequence is a
conflict, not an idempotent replay.

Activation joins the immutable snapshot row, reconstructs it from canonical
bytes, verifies both digests and all derived fields, and only then projects
JobIR. Missing rows and construction placeholders are rejected. The store
boundary also proves that target repository ID, execution ref, and execution
revision bind the same admitted origin.

Rerun creation copies the original snapshot inside the same durable operation.
The triggering actor is separately recorded by rerun/audit state, but the
source snapshot is not re-evaluated against current actor, repository, or
policy state. Thus a privileged user cannot upgrade a fork run by clicking
rerun, and a later policy revision cannot retroactively change an old run.

## Consumer requirements

Every consumer first verifies canonical bytes and digest coherence, then uses
the snapshot's exact authority decision:

- Repository token issuance applies the permission ceiling before minting and
  emits no token for `DenyAll`. Read-only reduction demotes writable scopes and
  drops write-only scopes.
- Secret resolution and runner custody reject normal secret delivery unless
  the snapshot says `Eligible`. Secret values never enter the snapshot.
- Cache credentials are partitioned by trust and are restore-only for fork and
  automation snapshots. Incomplete evidence receives no cache credential.
- Protected-environment entry is an eligibility gate; later environment policy
  and approval still apply.
- OIDC issuance requires both trust eligibility and all ordinary permission,
  lease, fence, and session proofs.
- Job outputs from restricted sources are marked untrusted; secret-derived
  output values are not published as plaintext.
- Results credentials preserve standard, untrusted, or denied authority
  exactly. A valid deny-all job may therefore carry an intentionally empty
  runtime-authority bundle rather than receiving fallback authority.
- Runner context decoding and protocol boundaries reject missing, mismatched,
  malformed, or noncanonical snapshot evidence before user work begins.

## Failure behavior

Admission or execution fails closed for at least these conditions:

- absent event-required actor, repository, ref, revision, fork, recursion, or
  upstream evidence;
- source/target identity contradicting the fork bit;
- Dependabot combined with a fork classification;
- privileged event origin or transition inconsistent with the event kind;
- upstream evidence on an event that cannot carry it;
- zero, excessive, incomplete, or internally inconsistent transitive chains;
- repository dispatch with suppressed or unknown recursion origin;
- rerun evidence that attempts fresh policy evaluation;
- unsupported policy/snapshot schema or media type;
- empty, oversized, malformed, noncanonical, or unknown-field JSON;
- policy digest, snapshot digest, persisted metadata, JobIR, or protobuf
  disagreement;
- target repository, execution ref, or execution revision disagreement at run
  origin;
- replay or insert-race evidence that differs from the immutable winning row.

Diagnostics name the failed contract but do not include raw webhook bodies,
credential values, secret values, or full canonical snapshot bytes. Debug
formatting for actor evidence is intentionally redacted.

## Verification matrix

The implementation is covered at several boundaries:

- pure truth-table tests for event, fork, Dependabot, automation, incomplete,
  recursion, privileged-transition, transitive, and policy combinations;
- canonical encoding, digest, unsupported-schema, altered-decision, and
  redacted-debug tests;
- typed GitHub event-envelope tests proving derivation from authenticated
  normalized facts and rejecting ambiguous evidence;
- store and PostgreSQL origin-binding, immutable persistence, exact replay,
  insert-race, and activation reconstruction tests;
- rerun tests proving byte-for-byte source snapshot reuse and triggering-actor
  non-escalation;
- JobIR and protobuf round-trip/tamper tests;
- product tests for repository tokens, secrets, cache, environment, OIDC,
  outputs, Results, and runner context.

Operationally, any new event ingress must add its completeness cases to the
truth table and prove that all consumers observe the same snapshot. Any policy
change requires a new policy revision and digest. Schema changes require a new
media type/version and an explicit migration; frozen migration baselines are
never edited.

---

[Back to event ingress, identity, and security](github-actions-parity-06-trust-security.md)
