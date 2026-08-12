# Source-of-truth and deployment model

## Principle

Every business fact has one authoritative owner. Other systems may hold a
versioned projection for routing, display, or local admission, but projections
must be rebuildable and must not become competing authorities.

Cloud and Core never join across databases. Cross-boundary changes use
authenticated, versioned APIs and durable events. Multi-step provisioning is a
recoverable workflow, not a distributed database transaction.

## Authority matrix

| Fact | Authority | Projections and notes |
| --- | --- | --- |
| GitHub account identity | GitHub | Cloud maps the GitHub subject to a Cloud account; Core maps the delegated external subject to a Core user |
| Cloud browser session | Cloud | Never accepted directly by Core |
| Workspace stable ID and commercial lifecycle | Cloud | The same stable ID is provisioned as a tenant in Core |
| Workspace slug, display name, trial and billing state | Cloud | Core needs only generic execution identity and entitlements |
| Tenant membership, invitations, roles, bindings, and execution authorization | Core | Cloud keeps a non-authoritative workspace-access index for navigation and routing, but Core reauthorizes every Core read and mutation |
| Workspace-to-shard route | Cloud | Initially every workspace points to the same shared shard |
| Shard endpoint, region, health, and supported protocol versions | Cloud/operations | Discovered from deployment health and release metadata |
| Choice of replica for one request | Load balancer | Never stored as tenant state; ordinary requests may hit any healthy replica |
| GitHub App installation existence and permissions | GitHub | Cloud owns installation-to-workspace routing; Core owns its execution-facing repository projection |
| Repository/workflow/run/job/attempt state | Core | Cloud renders or indexes only explicit API projections |
| Secrets and execution credentials | Core | Cloud must not receive plaintext execution secrets |
| Raw execution allocation facts | Core | Stable events are exported to Cloud at least once |
| Trial/paid pricing and billable usage ledger | Cloud | Derived from Core allocation facts and immutable price versions |
| Payment method, invoice, charge, and settlement state | Stripe | Cloud stores identifiers and a webhook/reconciliation projection |
| Subscription projection and commercial account state | Cloud | Derived from verified Stripe events plus administrative policy |
| Entitlement policy | Cloud | Core stores a signed/versioned generic projection for local admission |
| Live log stream and finalized log metadata | Core | Log bytes may live in runner spool, the Core data plane, and object storage according to lifecycle |
| Artifact/cache/log objects | Configured object store | Core owns object identity, tenant association, authorization, and retention metadata |
| Cloud audit events | Cloud | Covers commercial, account, routing, and Cloud administration actions |
| Core audit events | Core | Covers execution, tenant authorization, secrets, and Core administration actions |

## Shared-shard model

A Cloud tenant does not receive a Rust instance. Cloud routes a request to the
workspace's **shard**, and infrastructure load-balances it across healthy Core
replicas.

```text
                         one shared shard initially

Automata Cloud ──> internal Core load balancer ──┬── Rust replica A ──┐
                                                 ├── Rust replica B ──┼── shared PostgreSQL
Browser live logs ─> public data-plane LB ──────┴── Rust replica C ──┤
                                                                      ├── object storage
Runners ────────────> runner gateway pool ────────────────────────────┘
```

Round-robin, least-connections, or another normal balancing algorithm is an
infrastructure choice. The application contract is that an ordinary request
can reach any compatible healthy replica. Replicas do not contain authoritative
tenant state in memory.

Live connections may need routing by job attempt or log-stream identity if the
first fan-out implementation has an in-process owner. That is short-lived data
plane affinity, not assignment of a tenant to an instance. The preferred
eventual shape is that any log-serving replica can replay committed segments
and subscribe to the live tail.

## Shard routing and future scale

The Cloud directory stores a route resembling:

```text
workspace_id -> shard_id
shard_id     -> internal API audience and endpoint
             -> public data-plane origin
             -> region and health state
             -> supported protocol versions
```

It deliberately does not store `workspace_id -> replica`. Initially all
workspace rows can reference one shard. Later, the directory permits:

- moving a workspace to a different shared shard;
- placing new workspaces in another region;
- draining and replacing a shard release; and
- assigning a dedicated shard to an enterprise customer.

Moving a workspace between shards is a deliberate migration workflow because
Core owns tenant execution data. Changing a directory row alone is not a data
migration mechanism.

## Tenant storage rules

Within a shared Core database:

- Every tenant-owned row includes `tenant_id`.
- Tenant-scoped indexes and uniqueness constraints begin with `tenant_id`.
- Composite foreign keys prevent cross-tenant references where practical.
- Request and repository APIs receive a trusted tenant context; request bodies
  do not select their own tenant authority.
- PostgreSQL row-level security may provide defense in depth, but cannot replace
  application authorization or tenant-scoped query tests.
- Object keys are opaque and unguessable, while the authoritative object
  metadata binds every object to a tenant and resource.

The Cloud database uses the same discipline for Cloud-owned workspace data.
Cloud and Core can share a stable workspace UUID without sharing schemas,
connections, or transactional authority.

## Object-storage layout

Use object-storage buckets as shard and data-lifecycle boundaries, not as the
tenant authorization boundary. The initial production layout should have two
private buckets per shard:

```text
<deployment>-<region>-<shard>-results-<account-suffix>
<deployment>-<region>-<shard>-cache-<account-suffix>
```

- The **results bucket** contains finalized logs and artifacts. Enable
  versioning, server-side encryption with a shard-scoped KMS key, Block Public
  Access, retention/lifecycle rules, inventory, and audit logging. Add
  cross-region replication or AWS Backup when the product has an explicit RPO
  and RTO.
- The **cache bucket** contains reproducible workflow caches. Give it aggressive
  expiry and do not include it in disaster-recovery replication or backups by
  default.
- Keep tenant and repository names out of bucket names and object keys. Keys may
  contain opaque stable IDs, but Core object metadata remains authoritative for
  tenant ownership, resource association, hashes, and retention.
- Do not create a bucket or encryption key per tenant in the shared product.
  That creates control-plane quota and operational pressure without replacing
  Core authorization.

Amazon S3 does not impose a maximum bucket size or object count, so splitting
buckets is not required to avoid a petabyte-scale capacity ceiling. Per-shard
buckets are still useful because IAM, encryption, lifecycle, replication,
inventory, cost attribution, migration, and recovery can be operated one shard
at a time. Separating results from caches prevents cache churn from inflating
the protected data set.

A storage bucket is not by itself a consistent backup of a shard. PostgreSQL is
the metadata authority, while object data has its own versioning and replication
timeline. Recovery procedures must choose a database recovery point, reconcile
the referenced object inventory at that point, restore missing referenced
objects where possible, and quarantine or later collect unreferenced objects.

## Workspace provisioning state machine

Creating a workspace spans Cloud and Core and must survive interruption:

```text
pending_payment
    -> payment_method_ready
    -> core_provisioning
    -> active

Any nonterminal state may enter retryable_error or canceled.
```

1. Cloud generates the stable workspace ID and records the pending workspace.
2. Stripe-hosted collection produces a confirmed customer/payment-method
   projection.
3. Cloud sends an idempotent `ProvisionTenant(workspace_id, ...)` command to the
   selected shard.
4. Core creates or returns the matching tenant without duplicating it.
5. Cloud marks the route active only after Core confirms provisioning.

Retries use the same workspace ID and idempotency key. Cleanup and support
tooling can see the last successful step; no code assumes both databases commit
at once.

## Projection rules

- Every projection records its source version or event cursor.
- Duplicate delivery is harmless.
- Out-of-order delivery is rejected, deferred, or reconciled explicitly.
- Operators can replay or rebuild projections without editing production rows
  manually.
- The UI labels temporarily stale commercial state rather than guessing.
- Authorization fails closed when the necessary Core membership state is
  unavailable.

## Workspace-access index

Cloud needs to list the workspaces available to a signed-in account before it
can select a shard and request a Core page. It therefore stores a small index:

```text
cloud_account_id -> workspace_id -> shard_id
```

This is a navigation and routing projection, not an authorization database. If
the index is stale and lists a workspace after the person was removed, Core
returns `403`. If it temporarily omits a newly granted workspace, reconciliation
adds it; Cloud must not manufacture membership to repair the omission.

The index can initially be updated after successful provisioning and invitation
acceptance, then reconciled against Core. Membership-change events may reduce
the delay later without changing the authority boundary.

Generic invitations remain a Core feature so self-hosted deployments retain a
complete membership workflow. In Cloud, Node orchestrates authentication,
email, and browser presentation around Core-authorized invitation creation and
acceptance.
