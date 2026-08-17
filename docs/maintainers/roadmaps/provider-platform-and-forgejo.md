# Provider platform and Forgejo roadmap

- Roadmap status: Active
- Available provider: GitHub only
- Target provider: Forgejo 16.0.x
- Current checkpoint: A1 provider identity and capability foundation
- Date: 2026-08-18

This roadmap owns the refactor that separates source-hosting providers from
Automata's workflow language, migrates the complete GitHub integration onto
provider-neutral contracts, and then adds Forgejo. Every pull request in this
roadmap must remain below 10,000 changed lines. Forgejo implementation does not
begin until the GitHub migration is merged and its parity gate passes.

The result is a statically composed provider platform. Adding a later GitLab
adapter requires a new adapter crate, configuration schema, composition entry,
and conformance fixtures. It must not require another delivery worker, result
state machine, credential protocol, provider-specific store facade, or copy of
workflow orchestration.

## Outcome and limits

One Automata installation will be able to connect repositories from GitHub and
from any number of independently hosted Forgejo instances at the same time.
The provider instance is selected by durable connection identity, never by a
process-wide provider setting or an inferred hostname.

The first Forgejo release will support:

- push and pull-request admission from signed Forgejo webhooks;
- exact source resolution and archive retrieval for SHA-1 and SHA-256 Git
  repositories;
- changed-file evidence for supported push and pull-request shapes;
- commit-status publication with links to Automata results;
- scheduled and manually dispatched Automata workflows without pretending
  Forgejo has GitHub's native event types;
- read-only, attempt-bound checkout credentials from a dedicated Forgejo
  workload account;
- web and CLI login through OAuth authorization code with PKCE; and
- Forgejo organization and team evidence for Automata role mappings.

The first release will not provide:

- a Forgejo Actions runner or native `.forgejo/workflows` dialect;
- GitHub Check Run annotations, provider-native rerun buttons, or merge-queue
  events on Forgejo;
- a write-capable job token on Forgejo;
- transparent acceptance of untested Forgejo major versions;
- a runtime-loaded dynamic library ABI; or
- a data migration, dual-write period, legacy table aliases, old protocol
  decoding, or compatibility facades for the GitHub-shaped APIs being removed.

Automata continues to compile its existing GitHub Actions-compatible workflow
dialect. Names such as the `github` expression context and `GITHUB_TOKEN` are
syntax owned by that dialect, not evidence that the source host is GitHub. On a
Forgejo-backed run, the dialect adapter populates those fields from normalized
provider data. Supporting Forgejo Actions syntax or a future native Automata
dialect is separate work.

## Non-negotiable decisions

1. **Provider type and provider instance are distinct.** `forgejo` selects an
   adapter implementation. A durable UUID selects one configured Forgejo
   installation. Repository, user, and delivery identities are namespaced by
   the instance UUID.
2. **No provider mega-trait.** Delivery verification, source access, result
   publication, human identity, and workload credentials have separate
   capability-oriented ports. A provider bundle supplies only the ports it
   implements.
3. **Capabilities are explicit and fail closed.** Core services ask for a
   capability and port. They do not branch on `github`, `forgejo`, or a hostname.
4. **Provider payloads stop at the adapter.** Durable orchestration consumes a
   bounded normalized event plus an immutable raw-payload object reference.
5. **Provider-specific configuration is typed at the adapter edge.** The common
   store retains a bounded, versioned canonical document and separately
   encrypted named secrets. An adapter must decode and validate the document
   before use.
6. **Git object IDs carry their algorithm.** Exact commits are neither assumed
   to be SHA-1 nor represented as arbitrary revision strings.
7. **The schema cutover is destructive.** Development and unreleased
   installations reset their database. No compatibility views, aliases,
   backfill jobs, or dual reads are introduced.
8. **Static composition is the plugin boundary.** Provider crates implement
   stable Rust ports and register factories in the product composition. Dynamic
   libraries would add an unsafe ABI and deployment boundary without helping
   the current product.
9. **Forgejo job credentials are read-only in the first release.** Forgejo's
   token scope cannot safely reproduce the existing fine-grained GitHub
   permission map. Unsupported write requirements are rejected before a job is
   scheduled.
10. **GitHub is migrated before Forgejo code lands.** The interfaces must prove
    they can express the existing integration without regression before a
    second implementation pressures them.

## Current coupling to remove

The repository already contains a useful provider-neutral source boundary in
`automata-ci-scm`, but the complete product is still GitHub-shaped:

- `ExactRevision` accepts exactly 40 lowercase hexadecimal bytes;
- delivery identity requires a positive installation ID, although installation
  IDs are a GitHub App concept;
- provider manifests embed GitHub.com origins, API versions, Check Run policy,
  and GitHub archive limits;
- store traits and SQL expose GitHub manifests, schedules, result outboxes,
  service authorities, runtime authorities, subject evidence, permission
  observations, and repository dispatch directly;
- provisioning protobufs and application services model GitHub repository
  selection rather than provider connections;
- server composition constructs concrete GitHub services throughout the graph;
- the built-in runtime requirement is named `GithubToken`; and
- workflow parsing, expression evaluation, action metadata, execution, result
  transport, provider API access, and provider credentials all use `github` in
  crate names, even where the code implements workflow-dialect behavior rather
  than source-host behavior.

This is not solved by putting a `match provider_kind` around the existing
services. The GitHub-specific durable types and authority lifecycles must move
behind ports or into the GitHub adapter.

## Vocabulary and identity model

The refactor introduces these common identifiers:

| Type | Meaning | Representation |
| --- | --- | --- |
| `ProviderTypeId` | Adapter implementation such as `github` or `forgejo` | Bounded canonical lowercase string |
| `ProviderInstanceId` | One configured external service instance | UUID |
| `ProviderConnectionId` | One Automata repository connection | UUID |
| `ProviderWebhookEndpointId` | Public opaque ingress selector | Random 256-bit value encoded without provider name |
| `ExternalRepositoryId` | Provider-native repository identity | Bounded opaque string |
| `ExternalSubjectId` | Provider-native user, organization, or team identity | Bounded opaque string plus subject kind |
| `ExternalDeliveryId` | Provider-native delivery identity | Bounded opaque string |
| `GitObjectId` | Exact immutable Git object | `Sha1([u8; 20])` or `Sha256([u8; 32])` |

Provider-native numeric values are converted to canonical decimal strings at
the adapter edge. The common domain does not require them to be positive
integers. Display names, owners, repository paths, and network URLs are
attributes, not identity.

Every external identity key includes `ProviderInstanceId`. Two Forgejo servers
may both contain repository `42` and user `1` without collision. Repository
rename does not change a connection because the provider-native repository ID,
not `owner/name`, is authoritative. A webhook whose native repository ID does
not match the endpoint's bound connection is rejected even if its display path
matches.

`GitObjectId` parses only full canonical lowercase IDs and records the
algorithm. Branches, tags, and abbreviated hashes remain `RevisionSpec` values
until resolved. API, store, protocol, object keys, event evidence, result
subjects, and checkout requests all use the exact typed object ID.

## Accepted architecture

```text
                       provider factory registry
                   /              |               \
             GitHub factory   Forgejo factory   future factory
                   |              |
                   v              v
public webhook -> verifier -> event normalizer -> durable delivery service
                                               -> workflow admission
provider API <-> source / changed-files ports   -> immutable source evidence
provider API <-> result publisher port          <- desired result projection
provider API <-> identity ports                 -> common membership evidence
provider API <-> credential issuer port         -> lease-bound runner authority

          common store, scheduler, workflow compiler, runner protocol
```

The product composition owns a `ProviderFactoryRegistry`. Each configured
instance is decoded by the matching factory into a `ProviderBundle`:

```rust
pub struct ProviderBundle {
    pub descriptor: ProviderDescriptor,
    pub deliveries: Arc<dyn DeliveryAdapter>,
    pub source: Arc<dyn RepositorySource>,
    pub changes: Arc<dyn ChangedFileReader>,
    pub results: Arc<dyn ResultPublisher>,
    pub control_credentials: Arc<dyn ControlCredentialProvider>,
    pub workload_credentials: Option<Arc<dyn WorkloadCredentialIssuer>>,
    pub browser_auth: Option<Arc<dyn AuthorizationCodeProvider>>,
    pub device_auth: Option<Arc<dyn DeviceAuthorizationProvider>>,
    pub identities: Option<Arc<dyn IdentityReader>>,
    pub memberships: Option<Arc<dyn MembershipReader>>,
}
```

This is a composition bundle, not an interface that forces every provider to
implement every concern. Construction validates that the bundle's declared
capabilities match its present ports. Application services receive the narrow
port they need, not the entire bundle.

The registry is keyed by `ProviderTypeId`. Adding GitLab later changes the
product's dependency list and registry construction, but does not add a GitLab
variant to core types or a GitLab branch to services.

### Capability set

Capabilities are a closed common vocabulary with typed parameters where the
semantics differ:

- `SourceRead { object_formats }`
- `ChangedFiles { events, completeness }`
- `CommitStatus { states, history_model }`
- `RichChecks { annotations, actions }`
- `NativeRerunAction`
- `WorkloadRepositoryCredential { profiles, revocation }`
- `AuthorizationCodeLogin { pkce }`
- `DeviceAuthorizationLogin`
- `MembershipEvidence { subject_kinds }`
- `ManagedWebhook`
- `PullRequestEvent`
- `MergeQueueEvent`
- `RepositoryDispatchEvent`

Capabilities describe behavior; they are not strings copied from provider API
documentation. A workflow or service computes requirements, then resolves the
required port and capability parameters. Missing or weaker capabilities produce
a typed admission or configuration error before side effects.

### Crate ownership after the GitHub migration

The exact crate split may be adjusted to keep individual pull requests small,
but ownership must end in these groups:

| Group | Responsibility |
| --- | --- |
| `automata-ci-provider` | Common instance, connection, capability, factory, config, delivery, event, result, identity, and credential contracts |
| `automata-ci-scm` | Provider-neutral revision, Git object ID, source archive, and changed-file contracts |
| `automata-ci-provider-github` | GitHub API models, App/OAuth/webhook adapters, Check publisher, event normalization, and GitHub capability declaration |
| `automata-ci-provider-forgejo` | Forgejo v16 API models, PAT/OAuth/webhook adapters, status publisher, event normalization, and Forgejo capability declaration |
| `automata-ci-workflow-actions` | Existing Actions-compatible YAML frontend and compiler |
| `automata-ci-expression-actions` | Existing Actions-compatible expression language and `github` context semantics |
| `automata-ci-action-actions` | Existing `action.yml` metadata dialect |
| `automata-ci-actions-runtime` | Existing workflow-command and runtime-context behavior |
| `automata-ci-job-executor-actions` | Existing Actions-compatible job executor |
| `automata-ci-runner-results` | Provider-neutral runner-to-control-plane result transport |
| `automata-ci-workload-oidc` | Provider-neutral Automata workload OIDC authority; provider-native OIDC remains an adapter capability |

There will be no re-export shims under the old crate names. Cargo packages,
Rust imports, fixtures, documentation, and composition move together in bounded
rename pull requests.

## Provider contracts

### Configuration and factory contract

The common configuration record contains:

- instance UUID, provider type, enabled state, and monotonically increasing
  revision;
- canonical web origin and canonical API origin;
- bounded adapter schema version and canonical configuration bytes;
- named encrypted secret references and their generations;
- the capability digest returned by adapter validation; and
- creation, activation, and retirement evidence.

Common code validates URL syntax, HTTPS policy, document bounds, revision
ordering, secret custody, and digest integrity. The adapter validates its typed
document, permitted origins, API version, required secret names, and capability
combination. Unknown fields and schema versions fail closed. Adapter documents
are canonical serialized values, not unvalidated `serde_json::Value` passed
through application services.

Repository connections contain common policy such as workspace, provider
instance, external repository ID, visibility, default branch, workflow source
selection, runner policy, and archive limits. A bounded adapter-owned policy
document holds only behavior that cannot be expressed commonly. GitHub App
installation ID belongs there; it is not a field in common delivery identity.

### Webhook verification and event normalization

The ingress route is:

```text
POST /api/v1/provider-webhooks/{opaque_endpoint_id}
```

The endpoint record resolves the provider instance, connection, active secret
generation, body limit, and adapter type before parsing the payload. The public
path does not contain a provider name, repository name, or workspace ID.

`DeliveryAdapter` receives an exact raw method, selected headers, bounded body,
endpoint binding, and candidate secret generations. It returns either a
verified delivery or a sanitized rejection. Verification covers the raw body
before JSON decoding. The adapter accepts only its canonical header family;
Forgejo's GitHub-compatible aliases are not trusted.

A verified delivery contains:

- instance, connection, external delivery, event type, and received time;
- exact raw-body digest and immutable object reference;
- signature scheme and accepted secret generation evidence;
- normalized actor and repository identities;
- a strongly typed trigger event; and
- adapter observations needed to audit normalization, without secret or token
  material.

The initial normalized trigger variants are `Push`, `PullRequest`,
`MergeQueue`, and `RepositoryDispatch`. Schedule and Automata manual dispatch
enter admission through their own authenticated sources, not fabricated webhook
events. Provider-native event names are retained as evidence but never drive
core branches.

Unknown, unsupported, or incomplete event shapes are recorded with bounded
diagnostics and do not enter workflow admission. Duplicate external delivery
IDs on one provider instance are idempotent only when their raw-body digest,
endpoint, and event identity agree; conflicts are security failures.

### Source and changed-file contracts

`RepositorySource` accepts a connection, exact `GitObjectId`, explicit borrowed
credential, archive bounds, and redirect policy. It must prove that the returned
archive represents the requested object, stream within the compressed limit,
and return a locally calculated content digest. Mutable selectors are resolved
by a distinct call before admission records the exact object.

`ChangedFileReader` returns one of:

- `Complete { paths, evidence }`;
- `NotApplicable`; or
- `Incomplete { reason, evidence }`.

Pagination, truncation, compare gaps, force pushes, and provider response limits
must be represented. Path-filtered workflows reject `Incomplete` evidence
instead of treating a partial list as complete. Workflows without path filters
may proceed while retaining the incomplete observation.

Archive and API clients share an explicit redirect policy. Credentials are
never forwarded to a different authority, downgrade, or user-info URL. No
adapter reads ambient Git configuration, credential helpers, environment
tokens, or home-directory files.

### Desired result projection

The workflow service writes a provider-neutral desired projection keyed by
connection, exact commit, workflow/run subject, attempt, and projection
generation. It contains phase, conclusion, title, bounded summary, details URL,
and optional annotations. A generic outbox owns leases, retry, supersession,
and terminal failure. The adapter owns provider-specific reconciliation.

Publication capabilities distinguish:

- mutable rich checks with annotations and external actions;
- append-history commit statuses; and
- future external-pipeline/job models.

Core code does not manufacture a lowest-common-denominator provider object.
Annotations remain in Automata even when the provider cannot display them.
Native rerun actions are optional; the Automata API remains the universal rerun
surface.

Every adapter must prove idempotency under response loss. A retry first lists
or reads provider state, identifies objects by deterministic context and
Automata marker, and creates or updates only when the desired generation is not
already represented. Response order is never treated as recency without a
provider guarantee.

### Control-plane credentials

`ControlCredentialProvider` supplies credentials for provider API operations
outside jobs. Its strategies are explicit:

- `Minted` for short-lived, reconcilable credentials such as GitHub App
  installation tokens; or
- `Stored` for an encrypted operator-provisioned token such as a Forgejo
  repository token.

The returned credential includes its provider instance, connection scope,
allowed operations, generation, expiry when available, and revocation model.
Application services ask for operations such as source read, status write, or
membership read. They never ask for an undifferentiated token.

### Workload credentials

The workflow compiler reports the dialect-level built-in requirement as
`WorkflowRepositoryToken`, replacing `GithubToken`. The Actions-compatible
runtime exposes the issued value as `github.token` and
`secrets.GITHUB_TOKEN`; those names remain confined to the dialect crates.

`WorkloadCredentialIssuer` receives connection, exact repository, trust class,
requested permission profile, job, attempt, lease, and bounded lifetime. It
returns an authority bound to those values and a durable revocation identity.
The runner protocol remains provider-neutral and never contains a GitHub App
installation ID.

The common profiles are initially:

- `CheckoutRead`, which permits exact source fetch only; and
- `RepositoryWrite`, which is available only when an adapter proves a safe
  mapping for every requested permission.

Forgejo v16 implements only `CheckoutRead`. It uses a dedicated non-admin
workload account whose password is held in encrypted control-plane custody.
Before each attempt, the adapter creates a uniquely named, exact-repository
token with `read:repository`, durably records its external token identity, and
delivers the value through the existing lease-bound runtime-authority channel.
Completion, cancellation, lease loss, startup recovery, and indeterminate mint
all converge on token deletion. A deterministic token name allows an orphaned
token to be found and deleted when the create response was lost.

Forgejo's token-creation API requires Basic authentication and the issued token
has no server-enforced attempt expiry. The UI and operator documentation must
state this. The dedicated account must have access only to connected
repositories. A cleanup backlog makes new issuance fail closed after a bounded
threshold. Fault-injection tests cover a process crash before and after every
durable transition.

Any workflow requiring write access on Forgejo is rejected during admission.
This avoids broad `write:repository` PATs, webhook recursion, and a false claim
that Forgejo permissions match GitHub App permissions. A later write profile
requires its own threat model and roadmap change.

### Human authentication and membership

Human login is separate from repository control credentials. The common auth
service uses these narrow ports:

- `AuthorizationCodeProvider` for browser or loopback-PKCE login;
- optional `DeviceAuthorizationProvider`;
- `IdentityReader` for the authenticated external subject; and
- `MembershipReader` for bounded organization/team evidence.

GitHub retains web and device flows. Forgejo uses authorization code with PKCE
for both web login and a CLI loopback callback because Forgejo has no device
flow. The provider instance is part of login state, callback validation,
subject identity, token custody, membership snapshots, and role mappings.

Forgejo OAuth scopes do not restrict API rights. OAuth tokens are therefore
used only by the human identity service, are never substituted for control or
workload credentials, and are disclosed as broad credentials during setup.
State, nonce, PKCE verifier, redirect authority, expiry, and single-use callback
evidence remain bound as they are for the existing login service.

## Storage and provisioning cutover

The generic schema is organized by durable concern rather than provider name:

- `provider_instances`, revisions, active configuration, and secret bindings;
- `provider_connections`, repository selections, manifests, and endpoint
  bindings;
- `provider_deliveries`, attempts, raw-object evidence, and normalized events;
- `provider_result_subjects`, desired projections, outbox work, and publication
  evidence;
- `provider_schedule_*` and authenticated dispatch evidence;
- `provider_service_authorities` and control-credential issuances;
- `provider_workload_authorities`, issuances, delivery acknowledgements, and
  revocations;
- `provider_external_subjects`, membership snapshots, groups, and role
  mappings; and
- common capability and configuration digests attached to every record that
  depends on adapter behavior.

Common columns hold identity, lifecycle, bounds, digests, and invariants.
Adapter-owned canonical documents are used only for genuinely provider-specific
configuration and evidence. They are size-limited, schema-versioned, hashed,
and decoded by the owning adapter on read. Arbitrary JSON is not used for
common state transitions.

The provisioning API changes from GitHub-specific desired state to:

```text
ProviderInstanceDesiredState
  provider_type
  instance_id
  configuration_schema
  canonical_configuration
  named_secret_bindings

ProviderConnectionDesiredState
  instance_id
  external_repository_id
  common_repository_policy
  adapter_policy_schema
  canonical_adapter_policy
```

Provider factories validate desired state before the transaction commits.
Provisioning returns typed capability and configuration errors without secret
values. A workspace may select connections from multiple instances and types.

This is a destructive schema and protobuf replacement. The cutover procedure
is: stop all services, delete the unreleased database and durable test state,
deploy matching server and runner binaries, bootstrap the new schema, and
re-provision connections. Schema version mismatch prevents either an old or a
new binary from starting against the other schema. No old field numbers are
reused for different meanings.

## Forgejo adapter mapping

The initial adapter targets Forgejo 16.0.x. It probes `/api/v1/version`, accepts
major 16 only, records the observed version, and rejects other majors with a
configuration error. Each additional major needs a fixture/conformance lane and
an explicit supported-version change because Forgejo guarantees API
compatibility within a major, not across majors.

| Automata concern | Forgejo v16 mapping | Required behavior |
| --- | --- | --- |
| API base | `/api/v1` beneath configured API origin | Never infer a public cloud origin |
| API schema | Instance `/swagger.v1.json` plus checked-in minimal typed models | Do not generate unbounded provider models into core crates |
| Webhook delivery | `X-Forgejo-Delivery` | Bounded opaque identity |
| Webhook event | `X-Forgejo-Event` and documented subtype where applicable | Canonical Forgejo headers only |
| Webhook signature | lowercase hex HMAC-SHA256 in `X-Forgejo-Signature` | Constant-time comparison over exact raw body; no `sha256=` prefix |
| Push | Forgejo push payload | Validate instance, native repo ID, ref, before/after object formats, and actor |
| Pull request | Forgejo `pull_request` payload | Normalize supported actions and exact head/base identities |
| Source archive | `GET /repos/{owner}/{repo}/archive/{archive}` | Resolve by native ID/path evidence and verify requested exact object |
| Exact commit | `GET /repos/{owner}/{repo}/git/commits/{sha}` | Preserve SHA-1 or SHA-256 algorithm |
| Compare/files | Compare and pull-request files endpoints | Paginate or report incomplete evidence; enforce path/count bounds |
| Results | `POST /repos/{owner}/{repo}/statuses/{sha}` and status listing | Deterministic context/target marker; reconcile append-only history by identity, not response order |
| Control API credential | Encrypted exact-repository PAT where supported | Separate provisioning credential; minimum required scopes |
| Job checkout credential | Per-attempt repository-limited PAT created with Basic auth | Read-only, durable cleanup, no claimed server expiry |
| Web login | OAuth authorization code with PKCE | Exact configured origin and callback binding |
| CLI login | Browser plus loopback authorization code with PKCE | No emulated device flow |
| Membership | Authenticated user, organization, and team APIs | Bounded pagination and instance-namespaced subjects |

Result state mapping is explicit:

| Automata state | Forgejo status |
| --- | --- |
| queued or running | `pending` |
| succeeded | `success` |
| workflow failure | `failure` |
| infrastructure failure | `error` |
| neutral | `warning` |
| skipped or cancelled before execution | `skipped` |

Forgejo commit statuses do not provide GitHub Check annotations or external
actions. Those capabilities remain absent, detailed annotations stay in
Automata, and the status `target_url` links to the exact run attempt.

Local research against Forgejo 16.0.2 confirmed that push and pull-request
deliveries use the documented canonical headers, SHA-256 repositories produce
64-hex commit IDs and accept exact archive requests, and repeated status writes
with the same context create history rather than mutating one status. These
observations seed fixtures but do not become an availability claim until the
automated composition test passes.

Forgejo's documentation is authoritative for the initial implementation:

- [API authentication and major-version compatibility](https://forgejo.org/docs/latest/user/api/usage/)
- [webhook headers and HMAC verification](https://forgejo.org/docs/latest/user/repository/webhooks/)
- [access-token scopes and repository restrictions](https://forgejo.org/docs/latest/user/authentication/token-scope/)
- [OAuth authorization-code behavior](https://forgejo.org/docs/latest/user/authentication/oauth2-provider/)
- [differences between Forgejo Actions and GitHub Actions](https://forgejo.org/docs/latest/user/actions/github-actions/)

The interfaces were also checked against GitLab's substantially different
[webhook contract](https://docs.gitlab.com/user/project/integrations/webhooks/).
That comparison is a design check, not a commitment to implement GitLab in this
roadmap.

## Security and failure rules

All provider implementations must satisfy these invariants:

- Network origins are configuration, not provider defaults. Web, API, archive,
  OAuth, and redirect authorities are individually validated.
- Webhook authentication precedes parsing and durable normalization. Body and
  header limits apply before allocation grows with attacker input.
- A webhook endpoint is bound to one connection. Payload repository identity,
  provider instance, and endpoint binding must agree.
- Secret rotation accepts an explicit bounded set of generations and records
  which generation verified a delivery. It never tries every historical
  secret.
- Raw provider payloads are immutable evidence with a digest and retention
  policy. Logs and errors use normalized bounded diagnostics.
- External URLs, descriptions, branch names, user names, paths, status
  contexts, and API errors are untrusted bounded text. They never select local
  files or log unescaped secrets.
- HTTP clients have explicit connect, request, stream, and total timeouts;
  response byte limits; bounded pagination; and per-operation retry policy.
- Only idempotent reads retry automatically. Mutations reconcile provider state
  after timeouts or response loss before trying another mutation.
- Rate limits and transient outages preserve outbox work with bounded backoff.
  Authentication, capability, instance-version, and invariant failures are
  terminal until configuration changes.
- Provider credentials are separate by purpose: provisioning, control-plane,
  human identity, and workload. No fallback substitutes one class for another.
- Workload values enter only the existing lease-bound authority and masking
  path. Provider tokens are absent from job IR, durable command material,
  traces, diagnostics, and result payloads.
- Connection disablement closes ingress, stops new admission and issuance, and
  queues cleanup of outstanding workload credentials before retirement.
- Adapter capability and configuration digests are recorded with admissions
  and publications so a changed adapter cannot reinterpret old work silently.

## Test strategy

### Shared provider contract suites

Every adapter runs reusable contract tests for:

- identifier namespace isolation and repository rename;
- exact SHA-1 and SHA-256 parsing, resolution, and serialization;
- webhook body/header limits, signature rotation, replay, conflict, and
  cross-endpoint rejection;
- normalized push and pull-request invariants;
- changed-file pagination, truncation, force-push, and incomplete evidence;
- source redirects, streaming limits, mismatched commits, archive traversal,
  and credential non-forwarding;
- result projection idempotency, supersession, response loss, out-of-order
  history, rate limiting, and terminal failures;
- configuration schema/version rejection and capability/port consistency;
- secret redaction and absence from serializable/debuggable values;
- human-login state, PKCE, callback authority, subject namespace, and bounded
  memberships; and
- workload issuance, acknowledgment, cancellation, lease loss, orphan
  discovery, startup cleanup, and revocation backlog limits.

The contract suite supplies behavior tests, not a fake universal provider API.
Provider adapters retain focused tests for their signature formats, payloads,
HTTP models, permission mappings, and reconciliation algorithms.

### GitHub parity gate

Before Forgejo implementation starts, the complete GitHub composition must
pass:

- existing unit, integration, PostgreSQL, protocol, runner, and end-to-end
  tests under the renamed crates;
- webhook replay for push, pull request, merge group, and repository dispatch;
- exact archive, workflow admission, schedule, result annotation, rerun,
  control token, workload token, OIDC, browser login, device login, membership,
  and provisioning paths;
- simultaneous configuration of two GitHub provider instances without identity
  collision; and
- an allowlist search proving `Github*` store/application/protocol types remain
  only inside the GitHub adapter or Actions-dialect surface.

No Forgejo crate or fixture is merged before this gate. Research scripts and
throwaway local observations are not product dependencies.

### Forgejo conformance composition

CI starts a pinned official rootless Forgejo 16.0.x container with SQLite, a
throwaway administrator, a dedicated control identity, a dedicated workload
identity, a SHA-1 repository, and a SHA-256 repository. Setup uses the real API
and records only non-secret fixtures.

The acceptance lane proves:

1. provider instance and two repository connections can be provisioned;
2. signed push and pull-request webhooks reach one generic ingress and admit
   the exact source;
3. path filters receive complete evidence or fail closed on forced
   incompleteness;
4. SHA-1 and SHA-256 workflows compile and run through the ordinary runner;
5. queued, running, successful, failed, skipped, and infrastructure states
   converge to the expected commit-status history;
6. webhook replay and publication retry create no duplicate Automata run and no
   redundant terminal status;
7. a private checkout receives one read-only attempt token, masks it, and
   revokes it on success, failure, cancellation, lease loss, and server restart;
8. a write-token requirement is rejected before scheduling;
9. web and CLI PKCE login bind the correct Forgejo instance and membership
   evidence; and
10. GitHub and Forgejo repositories run concurrently in one Automata
    composition without shared identities, routes, credentials, or outboxes.

The test exports container logs and sanitized API evidence on failure, then
removes containers, volumes, networks, users, tokens, and repositories. Default
unit tests do not require the internet. Image updates and a new Forgejo major
are explicit dependency changes.

## Pull-request train

### Size and merge rules

Every pull request targets 8,500 changed lines or fewer so review fixes do not
cross the hard 10,000-line limit. The PR description records additions plus
deletions from the merge base, including generated files, fixtures, SQL, and
documentation. A check fails at 10,000. Large generated protobuf or fixture
changes get their own PR and are never hidden from the count.

Changed-line limits are ceilings, not targets. Each PR description also records
its net line change, deleted obsolete symbols/files, and dependency changes.
Review rejects duplicated old/new models, forwarding wrappers, re-exports,
unused dependencies, placeholder ports, and abstractions that have only a test
consumer but cannot yet express their final production contract.

Each PR has one architectural purpose, keeps the workspace buildable, and
leaves its changed vertical slice on the final contract. A foundational value
may precede its first production consumer only when its representation is
already final and the next PR needs it. Placeholder factories and partial
bundles are deferred until their real inputs and ports exist. No compatibility
facade, alias, dual-write path, or deprecated old interface is added. When a
caller migrates, the replaced interface is deleted in that same PR.

Schema-changing PRs update the bootstrap schema and matching code together and
require a development database reset. The series does not promise that an
unreleased database can survive between commits. Main remains internally
consistent and passes fresh-database tests after every merge.

### Stage A: foundations

| PR | Scope | Target lines | Merge evidence |
| --- | --- | ---: | --- |
| A1 Provider identity and capabilities | Add `automata-ci-provider`; instance/connection/external IDs; move the live connection ID out of store; add the typed capability vocabulary | 2,000-4,000 | Identity namespace and capability invariant tests; old store-owned ID and re-export are absent |
| A2 Git object identity | Replace 40-hex `ExactRevision` with algorithm-bearing `GitObjectId` across SCM, core records, protocol, object keys, and affected schema | 5,000-8,000 | SHA-1/SHA-256 round trips; uppercase, abbreviation, algorithm mismatch, and old protocol rejected |
| A3 Provider configuration and registry | Add canonical adapter config, named secret bindings, revision/digest lifecycle, connection manifest, final validation factory registry, and config-bearing bundle construction | 6,000-8,500 | Fresh PostgreSQL contract tests; two fake instance factories coexist; unknown schema/secret/capability fails closed |
| A4 Delivery foundation | Add opaque webhook endpoints, verified-delivery envelope, normalized trigger events, raw evidence, and generic delivery repository/worker ports | 6,500-8,500 | Fake adapters prove signature-before-parse, replay, conflict, rotation, and instance isolation |
| A5 Source and changed-file foundation | Extend SCM with connection-scoped exact source and completeness-bearing changed-file evidence | 4,000-6,500 | Shared archive, redirect, bounds, pagination, and incomplete-evidence tests |
| A6 Result projection foundation | Add desired projection, generic outbox, publication lease, capability descriptor, and publisher port | 6,000-8,500 | Fake mutable and append-history publishers pass response-loss and supersession tests |
| A7 Credential and identity foundation | Add control/workload credential strategies, generic runtime requirement, auth-code/device/identity/membership ports | 6,500-8,500 | Secret-safety, capability absence, lease binding, PKCE, and namespace tests |

Stage A adds no Forgejo implementation and changes no provider behavior beyond
the deliberate SHA-256-capable object/protocol break. Its interfaces are
reviewed as the permanent contracts before Stage B.

### Stage B: migrate and clean GitHub

| PR | Scope | Target lines | Merge evidence |
| --- | --- | ---: | --- |
| B1 Workflow dialect rename I | Rename workflow, expression, and action-metadata GitHub crates to the Actions dialect names; update imports and docs; no re-exports | 4,000-7,000 | Workspace and compiler golden tests unchanged semantically |
| B2 Workflow dialect rename II | Rename executor, runtime, runner-results, permissions, and workload-OIDC crates/types that are not host-provider adapters | 6,000-8,500 | Runner/protocol/result tests; provider-specific allowlist updated |
| B3 GitHub instance and source adapter | Move GitHub origins, App installation policy, API client, repository identity, source, and changed files into `provider-github`; register factory | 6,500-8,500 | Existing GitHub source tests plus common source contracts; two GitHub instances |
| B4 GitHub delivery adapter | Normalize GitHub events through the common envelope; move generic worker out of `github-delivery`; replace hard-coded route | 7,000-8,500 | Push/PR/merge-group/repository-dispatch replay and signature parity |
| B5 GitHub result adapter | Move Checks models/reconciliation behind `ResultPublisher`; migrate desired result outbox and rerun evidence | 7,000-8,500 | Annotations, actions, rerun, supersession, and lost-response parity |
| B6 GitHub control credentials | Move GitHub App service authority, installation token mint/reconcile, permission defaults, and revocation behind control credential ports | 7,000-8,500 | Indeterminate mint, expiry, permission, rotation, and revocation parity |
| B7 GitHub workload credentials | Move job token authority and fine-grained permission mapping behind `WorkloadCredentialIssuer`; remove GitHub fields from runner protocol | 7,500-8,800 | Lease, NACK, refresh, cancellation, masking, and cleanup parity |
| B8 GitHub schedules and evidence | Migrate schedules, authenticated dispatch, recursion policy, subject evidence, and manifest revisions to connection-scoped common records | 7,000-8,800 | Schedule/dispatch replay and trust-policy parity |
| B9 GitHub human identity | Move OAuth endpoints, device flow, user/team readers, membership snapshots, and role mappings behind identity ports | 6,500-8,500 | Web/device login, refresh, membership, revocation, and secret tests |
| B10 Generic provisioning | Replace GitHub-specific desired state/protobuf with provider instance and connection desired state; migrate GitHub decoder and CLI/API callers | 7,000-8,800 | Fresh provisioning, stale revision, secret rotation, disable/retire tests |
| B11 Store and SQL cutover I | Replace GitHub manifest/delivery/source/schedule/dispatch store traits, tables, and functions with the final common forms | 7,500-8,800 | Fresh PostgreSQL tests and schema mismatch rejection |
| B12 Store and SQL cutover II | Replace result/authority/identity/membership traits, tables, and functions; delete provider-specific store modules | 7,500-8,800 | Fresh PostgreSQL outbox, authority, and membership tests |
| B13 Product composition and purge | Build all services through the registry, support multiple instances, delete old GitHub crates/routes/config/schema symbols, and update operator docs | 6,000-8,500 | Full GitHub parity gate and strict name/coupling allowlist |

Some store records will move in the same vertical PR as their first adapter
consumer when that keeps compilation simpler. B11 and B12 are caps on the
remaining SQL work, not permission to leave two active models. The hard rule is
that no PR adds a bridge between the old and new models.

Stage B is merged completely before Stage C opens. The merge checkpoint is a
GitHub-only product with no Forgejo dependencies and no provider-specific
orchestration/store surface.

### Stage C: implement Forgejo

| PR | Scope | Target lines | Merge evidence |
| --- | --- | ---: | --- |
| C1 Forgejo client and instance factory | Add bounded Forgejo v16 HTTP models, version probe, typed config, control PAT custody, capability declaration, and source reads | 6,000-8,500 | Client fixtures, origin/redirect tests, private/public SHA-1 and SHA-256 source contracts |
| C2 Forgejo delivery and changes | Add canonical header/HMAC verification, push/PR normalization, webhook management adapter, compare and PR-file evidence | 6,500-8,500 | Real v16 push/PR fixtures, replay/conflict/rotation, pagination and incompleteness tests |
| C3 Forgejo result publisher | Add commit-status mapping and append-history reconciliation | 4,500-7,000 | All conclusion mappings, out-of-order list, lost response, retry, and no-op convergence |
| C4 Forgejo checkout credentials | Add dedicated-account Basic-auth mint, exact-repository read token, lease delivery, orphan discovery, and durable revoke worker | 7,000-8,800 | Crash matrix and private checkout acceptance; write profile rejected |
| C5 Forgejo human identity | Add OAuth authorization code with PKCE, CLI loopback flow, identity, organizations, teams, and role evidence | 6,000-8,500 | CSRF/PKCE/callback tests, broad-token separation, pagination, two-instance collision tests |
| C6 Forgejo provisioning and composition | Add provider desired-state decoder, webhook bootstrap, server/CLI configuration, mixed GitHub/Forgejo composition | 6,000-8,500 | Fresh install and disable/rotate/retire acceptance |
| C7 Forgejo end-to-end and documentation | Add pinned rootless v16 composition lane, fixtures, operator setup/recovery, compatibility update, and cleanup checks | 5,000-8,000 | Ten-point Forgejo conformance composition passes; docs claims updated from Planned to Available |

## Review checkpoints

Architecture review occurs after A3, A7, B5, B9, B13, C4, and C7. At each
checkpoint maintainers verify:

- the current branch diff is below the line budget;
- core services depend on capabilities and ports, not provider type checks;
- provider-specific types have not entered common store, protocol, workflow
  service, scheduler, or runner crates;
- no old API, table, route, configuration field, crate alias, or decoding path
  survives after its replacement;
- error and debug surfaces contain no secret values or raw unbounded provider
  data;
- fresh-database and affected end-to-end tests pass; and
- documentation uses Planned until the complete product path is proven.

Every PR, including those between architecture checkpoints, additionally runs a
removal audit: search for the replaced symbol family, inspect direct dependency
usage, compare additions and deletions, and identify every intentionally
remaining provider-specific name. A green build is not evidence that dead or
duplicated architecture is acceptable.

If a PR cannot satisfy the target line count, it is split by durable concern or
adapter capability before review. It is not split into a producer PR and a
compatibility-shim PR.

## Definition of done

This roadmap is complete when:

- the GitHub parity gate and Forgejo v16 conformance composition both pass in
  CI;
- one installation runs GitHub and two distinct Forgejo instances
  concurrently;
- SHA-1 and SHA-256 repositories complete private checkout and result
  publication;
- every provider-dependent application service receives a narrow common port;
- provider-specific SQL, protocol fields, application services, and
  provisioning messages are gone;
- GitHub host-provider code exists only in `automata-ci-provider-github` and
  explicit provider composition/tests;
- remaining `github` names elsewhere are reviewed and documented as
  Actions-compatible workflow-dialect syntax;
- no legacy or backward-compatibility path from the removed model remains;
- operator documentation covers Forgejo origins, v16 support, webhook setup,
  four credential classes, broad OAuth rights, workload-token cleanup, database
  reset, rotation, disablement, and recovery; and
- the compatibility page changes Forgejo from Planned to Available only after
  the end-to-end evidence is merged.
