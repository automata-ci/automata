# Page-model and mutation boundary

## Page resolution

The intended Core operation is conceptually:

```text
resolveCorePage(workspace, actor, logical route) -> exact CorePageModel v1
```

Cloud supplies service identity, a delegated actor assertion, the workspace ID,
and a bounded logical Core path/query. Core maps the actor, authorizes the read,
and returns an exact public UI page model. Cloud validates the model and renders
it through `@automata/ui-core`, adding only Cloud-owned document/navigation
slots.

This route is intentionally absent from `openapi-core.yaml` for the moment. The
current `ui/src/models.ts` TypeScript union and `ui/src/validation/` validators
are exact, but there is no exported language-neutral PageModel JSON Schema. A
permissive OpenAPI `object` would conceal that missing contract.

The UI extraction PR should produce:

```text
@automata/ui-core
├── schemas/page-model-v1.json
├── TypeScript PageModel types derived from the schema
├── validators
├── React pages/components/styles
└── conformance examples
```

The existing embedded `RenderRequest` remains a host contract containing
document assets, CSP nonce, locale, and the page. Cloud should consume the page
schema, not impersonate the embedded rendering host.

## Mutations

Do not add a generic “execute arbitrary Core mutation” endpoint. It would make
authorization, validation, client generation, observability, and compatibility
worse and could accidentally become an open proxy for Core routes.

Expose resource-specific mutation operations with exact schemas, for example:

```text
PUT /internal/v1/workspaces/{workspace_id}/repositories/{repository_id}/publication-policy
```

Its request would contain the expected resource/authorization revisions and the
new bounded policy. The actor comes from the signed assertion, not the body.
Core reauthorizes in the same transaction as the change and audit event.

Every mutation contract includes:

- stable `operationId` and HTTP method/path;
- exact params, headers, body, and response schemas;
- a UUID idempotency key;
- optimistic-concurrency revision where applicable;
- typed success, validation, forbidden, conflict, and unavailable outcomes;
- no caller-supplied role/permission authority; and
- no Cloud billing/product concepts.

Repository publication policy is the recommended first vertical-slice mutation.
It exercises identity delegation, current RBAC, resource scoping, optimistic
concurrency, audit, SSR refresh, and generated clients without transporting a
secret value. Once accepted, its exact Core domain inputs should become the
first mutation schema and OpenAPI route.

## Form capabilities

Core page models currently include host action paths, CSRF values, and revision
capabilities. Dual hosting requires separating browser-host CSRF from Core
mutation authority:

- Cloud owns its browser session and CSRF token.
- Core owns resource authorization and optimistic revisions.
- The Cloud page host maps a typed UI action to a typed Core client method.
- Cloud forwards the actor assertion, idempotency key, expected revision, and
  exact validated mutation—not arbitrary form fields or a browser cookie.
- Core performs current authorization again; rendering a button never grants
  lasting permission.

Self-hosted Core continues to render native forms and enforce its own browser
session/CSRF boundary. The shared page model may expose a host-neutral action
descriptor, while each host supplies its own form target and CSRF mechanics.
