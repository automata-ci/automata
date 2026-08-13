# Workspace provisioning v1

An authorized external control plane provisions one Automata workspace on one
Core shard through
`automata.management.v1.ShardManagementService/ProvisionWorkspace`.
Provisioning creates the Core tenant, maps the initial external human identity
to a Core-owned principal, and gives that principal the fixed initial-owner
membership. It does not grant compute entitlement.

The canonical RPC, request, response, failure detail, and optional HTTP mapping
are declared in
[`shard_management.proto`](../proto/automata/management/v1/shard_management.proto).
The version belongs to the Protobuf package and is not repeated as a scalar in
every message. This service is part of `core_http` protocol version 1 advertised
by the current shard-capabilities contract. That capability-family name is
retained for compatibility with existing clients; this management method uses
gRPC over HTTP/2 rather than the earlier handwritten JSON exchange.

This is a private service endpoint. A browser, CLI human session, runner, or
delegated actor assertion cannot call it.

## Vocabulary and identity

`workspace` is the product-facing name for Core's existing tenant boundary. In
version 1 they are the same identity:

```text
Cloud workspace_id == Core tenants.id
```

The wire value is a lower-case canonical UUID. Core may continue to use
`tenant_id` internally, but it persists this exact workspace UUID string and
must not generate a second tenant identifier. A workspace owns membership,
RBAC, repositories, runner groups, secrets, workflows, and execution records.
GitHub organizations are external provider resources, and repositories are the
initial project-level resource; this contract introduces no separate Automata
organization or project entity.

The initial owner is identified by `(issuer, subject)`, matching `iss` and `sub`
in the delegated actor contract. The subject is the external control plane's
stable account UUID. Core owns and generates `initial_owner_principal_id`.
Callers cannot select a Core principal, role, permission, or binding ID.

One exact external identity maps to one Core principal within a shard. That
principal may be a member of multiple workspaces. Core principal IDs are
shard-local implementation identities and must not become Cloud account IDs.
The supplied display names are non-authoritative labels and confer no identity
or authorization.

## RPC exchange

The request is bounded to 16 KiB before Protobuf decode. The caller supplies:

- a durable `operation_id` generated before its first network attempt;
- the expected `shard_id` already verified through shard capabilities;
- a control-plane-generated `workspace_id` and display label; and
- the initial owner's configured delegated-actor issuer, stable subject, and
  display label.

UUID values must be non-nil canonical lower-case UUID strings. The shard ID is
a stable lower-case operational slug of at most 63 characters. The issuer is an
absolute HTTPS origin without credentials, path, query, or fragment. Display
labels must be trimmed, nonblank Unicode text without control characters and at
most 255 Unicode scalar values. These are domain validation requirements in
addition to successful Protobuf decoding.

The first committed request and an exact replay both return gRPC `OK` with the
same `ProvisionWorkspaceResponse`. The response records Core's database commit
time and Core-owned principal ID; those values remain stable on replay.

Failures use an ordinary gRPC status and, when Core can safely construct it, a
typed `ProvisionWorkspaceFailure` in the richer status details:

| gRPC status | Failure reason | Meaning |
| --- | --- | --- |
| `INVALID_ARGUMENT` | `INVALID_REQUEST` | The request is malformed or violates a semantic bound. |
| `UNAUTHENTICATED` | `UNAUTHENTICATED` | Workload authentication is absent or invalid. |
| `PERMISSION_DENIED` | `FORBIDDEN` | The workload cannot provision on this shard or for this issuer. |
| `ABORTED` | `OPERATION_CONFLICT` | The operation ID is already bound to different request semantics. |
| `ALREADY_EXISTS` | `WORKSPACE_CONFLICT` | A different operation already owns the workspace ID. |
| `FAILED_PRECONDITION` | `PRINCIPAL_UNAVAILABLE` | The exact external identity maps to a disabled or inconsistent principal. |
| `RESOURCE_EXHAUSTED` | `RATE_LIMITED` | The workload exceeded its bounded provisioning rate. |
| `INTERNAL` | `INTERNAL_ERROR` | Core failed without a safe, more specific result. |
| `UNAVAILABLE` | `TEMPORARILY_UNAVAILABLE` | A required Core dependency is temporarily unavailable. |

An unimplemented package or method reports gRPC `UNIMPLEMENTED`; clients use
shard capabilities to avoid sending calls to an incompatible shard. Transport
or authentication failures that occur before safe method dispatch may omit the
contract-specific detail.

The client may retry `RESOURCE_EXHAUSTED`, `INTERNAL`, `UNAVAILABLE`, and
indeterminate transport failures with bounded backoff, but only with the same
operation ID and exact semantic request. It must not change the operation ID
merely because an outcome is unknown. Authentication, authorization,
validation, and conflict failures need operator or application reconciliation
rather than blind retries. A retryable response should carry bounded retry
information when Core can provide it safely.

## Optional HTTP and JSON projection

The Protobuf method declares `POST /internal/v1/workspaces` with
`google.api.http`. A deployment may expose that mapping through a reviewed
transcoder, but the initial Core implementation is required to serve only the
canonical gRPC method.

The projection uses standard ProtoJSON: field names are lower camel case and
the timestamp is an RFC 3339 string. Example request and response payloads are
provided under [`examples`](examples/). Both a first commit and replay map to
HTTP `200`; clients must not infer whether creation occurred from an HTTP status
code. A gateway must enforce bounded bodies, reject unknown JSON fields, and
map gRPC status details without weakening workload authentication.

This private projection is not Automata Cloud's public browser or third-party
API. Cloud owns and documents that separate HTTP/JSON surface.

## Workload authentication

Transport-level workload authentication is mandatory and independent from the
initial human identity. A deployment may use mutually authenticated TLS or a
provider-native workload identity, but plain private networking is not
authentication. TLS confidentiality and server authentication remain required.

Core configuration binds the authenticated workload principal to:

- permission to provision workspaces;
- the exact target shard; and
- the exact delegated-actor issuer it may install.

Core compares `shard_id` with its configured shard identity and
`initial_owner.issuer` with the issuer bound to the authenticated workload. It
does not accept an arbitrary issuer chosen by the request, discover trust from
that issuer URL, or treat the initial owner as the caller. Workload credentials,
request messages, and response messages must not be logged wholesale.

The delegated actor JWT is deliberately insufficient for this method. Before
provisioning there is no workspace membership against which Core could
authorize it; allowing that assertion to bootstrap its own authority would make
the claimed workspace self-authorizing.

## Atomicity and idempotency

Core validates the complete request, maps it into the versioned domain model,
derives a digest from its known semantic fields, and applies one database
transaction. Unknown Protobuf fields are ignored for forward compatibility and
never become authority or enter the semantic digest. The transaction:

1. reserves `operation_id` under the authenticated provisioning authority with
   the semantic request digest;
2. creates the tenant using the exact `workspace_id` and display name;
3. finds or creates the Core principal mapped to `(issuer, subject)`;
4. creates an active tenant membership;
5. creates and binds Core's immutable built-in initial-owner role using the
   Core-defined permission set;
6. records a value-free security audit event; and
7. stores the stable response before committing.

All effects commit together or none do. The implementation must use database
time for `provisioned_at` and database uniqueness or equivalent locking for the
operation, workspace, external identity, membership, role, and binding.

The idempotency namespace is the stable configured provisioning authority plus
`operation_id`, not an individual certificate, pod, connection, or credential
version. Credential rotation therefore preserves replay behavior. The
authenticated authority is server-derived and never accepted from a request
field.

An exact replay of the same operation ID and semantic digest returns its stored
response without repeating effects. Reusing an operation ID with different
semantics returns `OPERATION_CONFLICT`. A different operation targeting an
existing workspace returns `WORKSPACE_CONFLICT`, even if its labels happen to
match; callers must resume the original durable operation instead of adopting
an ambiguous workspace.

If the external identity already maps to the same active principal, the
transaction reuses it and grants membership in the new workspace. It never
reactivates a disabled principal as a provisioning side effect. A label is not
identity, but it is part of the operation's semantic request digest; changing a
label on replay conflicts. Later label changes require an explicit profile or
workspace-update contract.

## Post-provisioning boundary

Provisioning establishes identity and administration, not permission to run
customer code. A new workspace remains non-admitting until a separate,
authenticated entitlement operation succeeds. Replaying provisioning must not
reset a trial, change an entitlement, install a GitHub App, add repositories,
or create billing state.

After provisioning, human operations use the delegated actor assertion. Core
verifies its signature and exact issuer, maps `(iss, sub)` to the durable
principal, requires the route workspace to match `workspace_id`, and evaluates
the current membership and Core RBAC. Cloud never sends roles or permissions in
that assertion.

Workspace rename, suspension, deletion, ownership transfer, additional-member
invitation, GitHub App installation, entitlement publication, and shard
migration are intentionally outside version 1.
