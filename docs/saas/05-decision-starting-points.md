# Recommended starting points for open decisions

Status: proposed defaults for the first implementation. These are deliberately
small, reversible choices that let the Cloud/Core boundary be exercised before
production scale makes the trade-offs harder to change.

## Decision summary

| Area | Recommended first choice |
| --- | --- |
| Object storage | One results bucket and one cache bucket per shard |
| Cloud actor signing | ES256 with an asymmetric AWS KMS key and issuer-pinned JWKS |
| Cloud-to-Core workload identity | Private networking plus mutual TLS; actor JWT remains separate |
| First cross-boundary mutation | Change a repository publication policy |
| Shared UI contract | TypeBox-authored page and mutation schemas in the public UI package |
| Live-log fan-out | Durable Core segments plus PostgreSQL notification and polling |
| Shard names | Stable, non-customer operational slugs such as `prod-us-east-1-001` |

## Object storage and recovery

Use two private buckets per shard because results and caches have fundamentally
different recovery policies. Finalized logs and artifacts are durable customer
data; caches are expendable accelerators. The detailed layout is in
[Source-of-truth and deployment model](02-source-of-truth.md#object-storage-layout).

Enable versioning on the results bucket from its creation. Objects should be
immutable in normal operation, which limits the otherwise significant storage
cost of retaining full previous versions. Defer cross-region replication and
AWS Backup until the team states a target RPO and RTO, then test a coordinated
PostgreSQL-and-object recovery rather than treating either system in isolation.

Useful AWS references:

- [S3 bucket limits and unlimited bucket size/object count](https://docs.aws.amazon.com/AmazonS3/latest/userguide/BucketRestrictions.html)
- [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)
- [S3 replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html)
- [AWS Backup for S3](https://docs.aws.amazon.com/aws-backup/latest/devguide/s3-backups.html)

## Delegated actor signing and key rotation

Start with ES256 (`ECC_NIST_P256`) in AWS KMS for Cloud-issued actor assertions.
It has broad JOSE/JWK support in both Node and Rust, and the private key never
needs to leave KMS. Ed25519/EdDSA is also supported by KMS and remains a good
alternative, but ES256 is the more conservative integration choice for the
first vertical slice.

- Publish only public keys at an issuer-pinned JWKS endpoint.
- Give every key an opaque `kid`; overlap old and new verification keys for at
  least the maximum token lifetime plus cache and clock-skew allowance.
- Set the actor assertion lifetime to two minutes initially, with a hard maximum
  of five minutes in Core.
- Cache an assertion briefly per Cloud session, workspace, and shard so routine
  page requests do not require a KMS signing operation each time.
- On an unknown `kid`, Core performs one rate-limited JWKS refresh and otherwise
  fails closed. Keep an operator path for immediate issuer/key revocation.
- Keep signing behind an interface. Self-hosted Core can use local PEM/JWK keys;
  the Cloud deployment uses KMS. KMS must not become an OSS product dependency.

The first spike should sign in Node using KMS, verify in Rust from the JWKS, and
measure signing latency and cache effectiveness before building more routes.
AWS documents supported asymmetric key specifications and the guarantee that a
KMS private key does not leave the service in its
[asymmetric key reference](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html).

## Workload identity between Cloud and Core

The actor assertion answers “which person is acting?” It does not answer “which
service delivered this request?” Use a second, independent workload identity:

- Put the internal Core endpoint on private networking.
- Require mutual TLS for Cloud web/worker calls to internal Core APIs.
- Issue identities per workload role, such as `cloud-web`, `cloud-worker`, and
  `core-shard-001`, rather than sharing one API key or certificate across all
  pods.
- Authorize service-only routes by workload identity and route allowlist. A
  browser-delegated Core route additionally requires the actor assertion.
- Use Kubernetes NetworkPolicy/security groups as another containment layer;
  they do not replace application authentication.
- Automate short-lived certificate issuance and rotation with cert-manager and
  a private CA. Defer a service mesh or SPIFFE/SPIRE until service count and
  operational needs justify it.

AWS's EKS guidance describes mutual TLS using ACM Private CA and cert-manager in
its [network-security recommendations](https://docs.aws.amazon.com/eks/latest/best-practices/network-security.html).

## First cross-boundary mutation

After a read-only repository page works end to end, implement one deliberately
boring mutation:

```http
PUT /internal/v1/workspaces/{workspace_id}/repositories/{repository_id}/publication-policy
```

The request carries an actor assertion, an idempotency key, the expected
resource revision, the expected authorization revision, and the desired policy.
Core checks current tenant membership and RBAC, performs an optimistic
concurrency check, writes the change and audit record transactionally, and
returns the new resource revision.

This proves delegated identity, Core-owned authorization, stale-page behavior,
idempotency, audit, generated clients, validation, and UI error handling without
entangling billing. Invitations are a useful second mutation because they also
exercise the Cloud email/presentation layer around a complete Core feature.

## Shared UI and schema ownership

Move shared React components, page-model schemas, mutation schemas, and
framework-neutral rendering helpers into a public `@automata/ui-core` package.
Author the TypeScript contracts with TypeBox so the same definitions provide
static types, runtime validation, JSON Schema, generated API documentation, and
client generation inputs.

Keep host concerns outside the shared package:

- The OSS QuickJS host owns its document shell, asset loading, CSP, sessions,
  and CSRF integration.
- The private Cloud SSR host owns its document shell, Cloud navigation,
  commercial pages, Stripe flows, and Cloud sessions.
- Cloud-only components can compose public components; the public package must
  never import from the private application.

Do not begin with a big UI extraction. Convert one repository page and its
mutation end to end. Rust can continue to use its native domain types and prove
schema conformance with integration fixtures initially; generating Rust types
from JSON Schema can be evaluated after the contract stabilizes.

## Live-log fan-out

Avoid introducing Redis, Kafka, or sticky tenant routing for the first version.
Treat committed Core log segments as the durable replay source, and use
PostgreSQL `LISTEN`/`NOTIFY` only as a wake-up signal containing a stream ID and
latest cursor—not log bytes.

Any Rust replica can then:

1. authorize the narrow log capability at connection establishment;
2. replay committed segments after the browser's cursor;
3. subscribe for notifications and query newly committed segments; and
4. poll periodically as a fallback because notifications are not durable.

Start with a 60-second capability lifetime for establishing the connection, a
15-second heartbeat, and a 15-minute maximum connection lifetime. The browser
reconnects through Cloud for a fresh capability and resumes from its last
cursor. Configure load-balancer idle timeouts above the heartbeat interval.

This preserves the “any replica” rule and makes missed notifications harmless.
Introduce a dedicated broker only after measurements show PostgreSQL wake-ups
or polling are a bottleneck, or if the runner/Core path cannot expose committed
segments quickly enough.

## Shard identity and naming

Use `shard_id` consistently in protocols and databases. Begin with a stable,
lowercase operational slug:

```text
prod-us-east-1-001
staging-us-east-1-001
```

The slug is allocated once and never renamed. It must not contain a customer,
repository, or company name. Cloud's shard directory maps it to internal and
public endpoints, region, health, and protocol capabilities. Derive readable
resource names from it where useful, adding an account-specific suffix where a
provider requires globally unique names.

A future move between shards is an explicit data migration. Reusing or editing
a slug must never masquerade as moving the underlying data.

## Suggested implementation order

1. Publish the package/repository dependency policy so private Cloud code can
   depend on public packages but not the reverse.
2. Prove KMS signing in Node and JWKS verification in Rust.
3. Extract one TypeBox-backed repository page contract into the public UI
   package and render it in both hosts.
4. Add the repository publication-policy mutation with revision and idempotency
   semantics.
5. Implement a one-shard directory entry and two-bucket storage convention in
   infrastructure code.
6. Prototype replica-independent live-log replay and tailing with durable
   segments plus PostgreSQL notification/polling.
