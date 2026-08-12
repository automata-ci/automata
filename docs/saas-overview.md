# SaaS product overview

This page records the initial product and system direction for a hosted Automata
service. The SaaS capabilities described here are planned. They are not claims
about the current product path.

Automata will replace GitHub Actions execution, not GitHub. Users will keep
their repositories and workflow files on GitHub, then connect those repositories
to an Automata workspace. The first hosted offering targets individuals and
small teams; dedicated deployments, data residency, enterprise SSO, and custom
contracts can wait until demand justifies them.

## Initial product shape

- Offer managed Linux execution and bring-your-own-runner (BYOR) execution.
- Charge for managed execution at per-second granularity.
- Keep BYOR execution free of compute charges, subject to a later product and
  support policy.
- Provide a self-service signup, onboarding, billing, and account-management
  path.
- Keep an enterprise contact path without building isolated enterprise
  infrastructure into the first release.
- Preserve a path to stronger tenant isolation and regional placement without
  making either a prerequisite for the initial control plane.

The first release should make a narrow path dependable: sign in, create a
workspace, connect a GitHub organization or account, select repositories, add
billing, and run a compatible workflow on managed capacity.

## Workspaces and tenancy

An Automata workspace is the tenant and billing boundary. It should not be
assumed to have a one-to-one relationship with a GitHub organization: one
workspace may connect multiple GitHub App installations, and one user may
belong to multiple workspaces.

- Use a shared PostgreSQL database and shared schema initially.
- Put `tenant_id` directly on every tenant-owned row, including high-volume
  execution and billing rows.
- Start tenant-scoped indexes and uniqueness constraints with `tenant_id`.
- Use composite foreign keys where they can prevent cross-tenant references.
- Require repository and service APIs to receive an authenticated tenant
  context rather than accepting a tenant identifier from request bodies.
- Consider PostgreSQL row-level security as defense in depth, with explicit
  roles for migrations and controlled cross-tenant operations.
- Use workspace-scoped URLs, for example `/w/{workspace}/runs`.

Adding `tenant_id` alone does not make the system shard-ready. Global lookup
tables should map GitHub installations, repositories, Stripe customers, and
Stripe subscriptions to a tenant. A small tenant directory can later map each
tenant to its database shard while all tenants still point to the same database
at first.

## Identity, membership, and onboarding

- Use GitHub OAuth for human sign-in.
- Keep Automata workspace roles and membership separate from GitHub
  organization membership.
- Use GitHub App installations for repository discovery, webhooks, and
  repository-scoped credentials.
- Support multiple installations per workspace and an explicit installation
  claim flow.
- Model invitations, membership removal, ownership transfer, and the loss of a
  user's GitHub organization access.
- Record security-sensitive membership, installation, billing, and suspension
  changes in the audit log.

The onboarding flow should handle GitHub events arriving before or after the
browser callback. Repository additions, removals, renames, transfers, visibility
changes, installation suspension, and permission changes all need idempotent
reconciliation rather than one-time setup logic.

## Billing and usage metering

Automata will calculate billable usage at one-second granularity in its own
durable ledger. Stripe will receive that usage asynchronously for invoicing;
Stripe is not the source of execution truth and the scheduler must not depend on
a synchronous Stripe request.

- Bill managed execution from successful sandbox resource allocation until the
  resources are released.
- Do not bill queueing or placement time.
- Record the runner profile, allocated resources, timestamps, tenant, job,
  attempt, billing disposition, and immutable price version for every usage
  interval.
- Make ledger entries idempotent, append-only, and traceable to the execution
  attempt that produced them.
- Define retry policy before charging: user-code failures are normally
  billable, while platform-caused retries and failed allocations should not be.
- Treat cancellation as billable until managed resources are actually
  released.
- Aggregate ledger entries into Stripe meter events through a durable outbox.
- Reconcile the local ledger, Stripe's recorded usage, customer invoices, and
  infrastructure cost.
- Run shadow metering before charging customers and compare measured usage with
  host occupancy and expected invoice totals.

Pricing still needs decisions about included credits, compute profiles,
minimum billable duration, rounding at invoice boundaries, storage and network
charges, taxes, refunds, and promotional credits.

## Plans and entitlements

The control plane should maintain a local entitlement snapshot derived from
the customer's plan, subscription state, credits, and administrative overrides.
Admission checks read this snapshot transactionally; they do not call Stripe.

Initial entitlements may include:

- access to managed execution and BYOR;
- allowed machine profiles and operating systems;
- workspace and repository concurrency limits;
- job runtime and monthly spending limits;
- artifact, log, and cache retention;
- trial or promotional credit balance; and
- account states such as trialing, active, grace period, suspended, and closed.

Stripe webhook delivery needs a durable inbox, event deduplication, replay, and
periodic reconciliation because events can be duplicated, delayed, or received
out of order. During a payment grace period, existing jobs should be allowed to
finish and users should retain access to data and billing controls, while new
managed jobs may be blocked.

## Managed execution and isolation

Dedicated enterprise instances can wait; strong isolation between untrusted
jobs on shared managed infrastructure cannot. The current rootless Podman
provider is suitable for trusted or customer-managed runners, not as the final
boundary for arbitrary hosted workloads.

The managed provider must define and enforce:

- a per-job isolation boundary and reliable teardown;
- CPU, memory, disk, process, and runtime limits;
- network and metadata-service policy;
- workspace, cache, artifact, log, secret, and credential transfer boundaries;
- image provenance, guest updates, and vulnerability response;
- crash recovery and orphan cleanup;
- capacity admission, warm-pool behavior, and autoscaling; and
- auditable measurements for resource occupancy and billing.

Firecracker is the selected isolation boundary for the first managed Linux
provider, with Cloud Hypervisor retained as the leading fallback if Firecracker
cannot meet a concrete compatibility or operational requirement. Automata will
own the provider integration and guest agent rather than building a custom VMM.
The remaining design work includes the guest/container architecture, image and
snapshot lifecycle, nested container support, networking, host hardening,
capacity management, and recovery behavior.

## Abuse and financial controls

A public CI service runs untrusted code and can incur costs faster than it can
collect payment. Limits and response paths belong in the first managed beta.

- Require a payment method or impose a small, capped trial.
- Set conservative concurrency, runtime, profile, and spending limits for new
  accounts.
- Rate-limit sign-in, installation, dispatch, artifact, cache, and API paths.
- Detect unusual job volume, duration, network traffic, and account creation.
- Restrict privileged execution, host devices, nested virtualization, and
  outbound network behavior according to an explicit policy.
- Support workspace suspension, job cancellation, evidence retention, appeal,
  and administrative audit trails.
- Publish acceptable-use and billing policies before opening self-service
  managed execution.

The unit economics model should include idle capacity, warm pools, image
distribution, storage, network egress, database and object-store operations,
payment fees, failed jobs, promotional usage, and support—not only VM runtime.

## Data lifecycle and operations

- Define retention periods for logs, artifacts, caches, audit records, billing
  evidence, and deleted workspaces.
- Build physical object garbage collection before a public managed beta.
- Specify cancellation, export, deletion, recovery, backup expiry, and legal
  retention behavior.
- Keep billing evidence long enough to explain and correct an invoice after
  ordinary execution data expires.
- Establish service-level indicators for job pickup, startup, completion,
  infrastructure failure, webhook delay, and billing reconciliation.
- Provide support tooling that is tenant-scoped, audited, and safe to use
  without direct production database edits.

## Suggested delivery sequence

1. Write decision records for tenancy, onboarding, metering, entitlements, and
   the managed isolation boundary.
2. Remove singleton-tenant assumptions and support workspace selection and
   dynamic GitHub App installations.
3. Add an explicit server role selector to the `automata` binary so web,
   ingress, results, runner-gateway, and background-worker roles can be deployed
   and scaled independently without splitting the modular monolith into
   microservices.
4. Deliver a no-charge onboarding path through repository synchronization and
   compatibility feedback.
5. Add the immutable local usage ledger, shadow metering, and a customer usage
   page.
6. Integrate Stripe test-mode checkout, customer portal, webhook inbox,
   subscription projection, usage outbox, and reconciliation.
7. Introduce managed capacity behind the selected strong-isolation provider.
8. Add abuse controls, retention and deletion workflows, operational tooling,
   and invoice reconciliation before a managed public beta.

## Open decisions

- Firecracker guest/container architecture and the criteria for falling back to
  Cloud Hypervisor.
- Initial machine profiles, regions, concurrency limits, and prices.
- Trial design, included credits, and payment-method requirements.
- Exact billing clock, rounding, credits, refunds, and platform-failure policy.
- Network egress and metadata-service policy for hosted jobs.
- Artifact, log, cache, audit, and billing-record retention periods.
- Tax collection, invoice ownership details, and supported billing countries.
- Conditions that would justify a dedicated deployment or regional shard.
