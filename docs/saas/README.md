# Automata SaaS planning packet

Status: working draft, 2026-08-12. These documents are intentionally
uncommitted while the team reviews the initial Cloud boundary.

This packet turns the high-level [SaaS product overview](../saas-overview.md)
into the first concrete product and system contracts:

1. [MVP user journey](01-mvp-user-journey.md)
2. [Source-of-truth and deployment model](02-source-of-truth.md)
3. [Cloud-to-core protocols](03-cloud-core-protocol.md)
4. [Failure and security model](04-failure-security.md)
5. [Recommended starting points for open decisions](05-decision-starting-points.md)
6. [Version-one contract drafts](contracts/v1/README.md)

## Confirmed direction

- Automata Cloud is a private TypeScript modular monolith with `web` and
  `worker` roles and its own PostgreSQL database.
- The public Rust application remains a complete self-hosted product and the
  execution control plane used by Cloud.
- Core retains its built-in GitHub authentication, membership, invitation,
  session, and RBAC capabilities. SaaS adds Cloud as a trusted external identity
  issuer; it does not replace or remove those open-source features.
- In SaaS mode Cloud authenticates the browser, while Core maps the signed
  external subject to a principal and authorizes every Core operation from its
  current durable membership and RBAC state. Cloud tokens never carry
  authoritative Core roles.
- Cloud tenants share an Automata deployment, database, and pool of Rust
  replicas. A tenant is not assigned to a Rust process.
- Cloud calls a load-balanced Automata shard. The shard may contain any number of
  equivalent Rust replicas.
- Browser control-plane traffic goes through Automata Cloud. Explicit
  capability-scoped data-plane traffic, beginning with live job logs, may go
  directly to a public Rust endpoint.
- The initial trial requires a payment method, lasts seven days, and includes
  100 minutes of managed compute.
- Stripe handles card entry and payment details. Automata never receives raw
  card data.

## Terminology

- **Workspace:** the customer-facing tenant, membership, and billing boundary.
- **Cloud:** the proprietary global web/API/worker application.
- **Core:** the public Rust Automata application and its APIs.
- **Shard:** one logical Core deployment: a load-balanced replica pool plus its
  database, object storage, runner gateways, and other shared dependencies.
- **Replica:** one interchangeable Rust server process or pod within a shard.
- **Runner:** a machine agent that leases and executes jobs.
- **Control plane:** account, navigation, configuration, admission, and
  commercial operations.
- **Data plane:** high-volume or latency-sensitive execution traffic such as
  runner protocols, live logs, and object downloads.
- **Workspace-access index:** Cloud's non-authoritative account-to-workspace
  projection used for navigation and routing. Core membership remains the
  authorization authority.

Initially there may be only one shared shard. This preserves a future route to
regional shards and dedicated enterprise deployments without
pretending that each tenant has a separate server today.

## Decisions that remain open

- Paid plans, machine profiles, prices, included usage, and spending limits.
- Trial conversion reminder schedule and supported billing countries.
- Whether the proposed live-log PostgreSQL notification/polling design meets
  latency and database-load targets.
- Exact Rust schema-conformance tooling and TypeBox package boundaries.
- Disaster-recovery RPO/RTO and when results-bucket replication becomes
  required.
- The first production region and the conditions for introducing another shard.
