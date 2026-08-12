# MVP user journey

## Goal

The first hosted release proves one narrow path: a developer can connect
GitHub, start a card-backed trial, run a compatible workflow on managed
capacity, watch it execute, and understand the usage that Automata measured.

The first audience is individuals and small teams. Enterprise SSO, dedicated
deployments, data residency, negotiated contracts, and a broad plan catalogue
are not MVP requirements.

## Signup and onboarding

1. The user signs in to Automata Cloud with GitHub OAuth.
2. Cloud creates an account and a pending workspace, or lets an invited user
   enter an existing workspace.
3. A new workspace is sent through Stripe-hosted payment-method collection.
   Trial activation requires a valid reusable payment method. Automata stores
   Stripe identifiers and safe display metadata only, never raw card details.
4. Cloud activates the workspace and its trial after Stripe confirms the
   payment method.
5. The user installs the Automata GitHub App and explicitly claims the
   installation for the workspace.
6. The user selects repositories. Automata reconciles their current repository
   state and reports initial workflow compatibility.
7. The user runs a workflow on the single trial-eligible managed machine
   profile.
8. The run page is rendered by Cloud from a Core-owned page model. While the
   job is active, the browser consumes a capability-scoped log stream directly
   from the Rust data plane.
9. The usage page shows consumed and remaining trial compute based on
   Automata's own usage ledger.

Existing workspace invitations should not require each invited member to enter
a card. The payment method belongs to the workspace billing account, not to an
individual member.

## Trial policy

The working product policy is:

- A seven-day wall-clock trial.
- 100 managed compute minutes, represented internally as 6,000 seconds.
- A reusable payment method is required before the trial starts.
- The trial clock starts when payment-method collection succeeds and the
  workspace is activated.
- The allowance is pooled across the workspace, not granted per user or per
  repository.
- Only the smallest initial machine profile is available during the trial, so
  “100 minutes” has an unambiguous resource and cost meaning.
- One wall-clock second of an allocated trial machine consumes one trial
  second. Queue time and failed placement do not consume the allowance.
- Trial eligibility, time expiry, compute allowance, profile access, and
  concurrency are separate generic entitlements even if the first UI presents
  them as one offer.

Managed trial admission ends when either the seven days expire or the included
compute is exhausted. If compute runs out first, Automata blocks new managed
jobs and offers an explicit **Start paid plan now** action. It does not begin
usage billing early merely because the allowance was consumed.

An already-running job should normally be allowed to reach a terminal state
rather than being killed at the exact credit boundary. The initial trial must
therefore use conservative concurrency and job-runtime limits so any overrun is
bounded. Its full measured usage remains visible in the ledger.

Unless the customer cancels, the subscription converts to the selected paid
plan at the end of the seven-day period and Stripe charges the saved payment
method under the price the customer accepted at signup. The UI must show the
conversion date and price before trial activation. Cancellation before that
date prevents the paid charge; data access and deletion then follow the normal
retention policy.

## Billing and risk controls during signup

- Use Stripe-hosted Checkout or an equivalent Stripe-hosted collection flow to
  minimize card-data scope.
- Verify Stripe webhook signatures and process events through a durable inbox.
- Make callback and webhook processing idempotent; browser completion is not
  proof that Stripe state changed.
- Require the card only for the workspace's managed Cloud trial. GitHub login
  and accepting an invitation remain possible without collecting another card.
- Apply conservative trial concurrency, runtime, profile, repository, and
  account-creation limits.
- Do not authorize an unbounded amount or silently charge trial usage.
- Send a clear reminder before automatic conversion and surface cancellation
  in the ordinary product UI.

## End of trial states

| Condition | New managed jobs | Existing jobs | Product behavior |
| --- | --- | --- | --- |
| Trial active with allowance | Allowed within limits | Continue | Show time and usage remaining |
| Allowance exhausted early | Blocked | Normally finish | Offer explicit early conversion |
| Trial time expired, payment succeeds | Paid entitlements apply | Continue | Begin paid metering |
| Trial time expired, payment fails | Blocked after defined grace policy | Normally finish | Show billing recovery path |
| Customer canceled | Blocked at trial end | Normally finish | No automatic paid charge |
| Workspace suspended for abuse | Blocked | Policy-dependent cancellation | Preserve an audited reason |

## MVP success criteria

- A new user can reach their first compatible run without staff intervention.
- Duplicate OAuth callbacks, GitHub webhooks, and Stripe webhooks do not create
  duplicate workspaces, installations, subscriptions, or credits.
- Every managed allocation produces traceable usage, including failed user
  jobs and excluded platform failures.
- The UI and Cloud support tooling can explain why execution was admitted or
  denied.
- Trial usage is reconciled against host occupancy before paid metering is
  enabled.
- Removing or suspending a GitHub installation predictably revokes access and
  stops new affected executions.

## Deferred product decisions

- Paid price and whether a paid plan includes monthly compute.
- Taxes, currencies, invoice identity, and supported countries.
- Exact reminder cadence before conversion.
- Refund and service-credit policy.
- Whether BYOR is offered inside Cloud at MVP and what Cloud features remain
  available after a managed trial ends.
