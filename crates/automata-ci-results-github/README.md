# GitHub Actions Results compatibility

`automata-ci-results-github` implements the Results artifact upload slice exercised by
`actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`
(v7.0.1, `@actions/artifact` 6.2.0). It is an HTTP adapter around neutral
application, repository, immutable-object, clock, identity, and credential
ports; GitHub protocol types do not leak into the scheduler or runner core.

It also implements the current JSON Twirp `CacheService` v2 surface used by
`actions/cache` 5.0.5: `CreateCacheEntry`, `FinalizeCacheEntryUpload`, and
`GetCacheEntryDownloadURL`. Request and response fields use protobuf field
names (`key`, `version`, `restore_keys`, `size_bytes`, `ok`,
`signed_upload_url`, `message`, `entry_id`, `signed_download_url`, and
`matched_key`); protobuf `int64` values use decimal strings while compatible
numeric requests are also accepted. The runner advertises
`ACTIONS_CACHE_SERVICE_V2=true` only with the composed Results service and
injects the same short-lived `ACTIONS_RUNTIME_TOKEN` used for authentication.

Cache runtime JWTs require an authenticated repository claim and a string
`ac` claim containing bounded `{"Scope": ..., "Permission": 1|2|3}` entries.
The server derives those entries from verified current JobIR evidence; cache
requests cannot supply or widen them. This phase supports the exact current
Git reference only. Pushes and canonical pull-request merge refs may write;
events whose write safety is not proven remain read-only. Base/default-ref
fallback is deliberately absent until immutable event evidence can authorize
it without trusting action input.

Cache entries are immutable and scoped by durable repository, ref, key, and
version. Lookup checks the current ref in exact-primary, primary-prefix, then
ordered restore-prefix order and selects the newest finalized match. Reads may
cross workflow runs in the same repository, while repository mismatches are
non-authorizing. PostgreSQL owns fencing, block-list commits, last access,
seven-day inactivity retention, and the 10 GiB repository quota with
least-recently-used eviction. The immutable-object store is never listed.
Signed downloads support `HEAD`, full `GET`, and single byte ranges with
`206`/`416` semantics.

An ignored offline integration fixture runs the exact `@actions/cache` 5.0.5
client supplied through `AUTOMATA_TEST_ACTIONS_CACHE_MODULE`; it performs no
package download. BuildKit compatibility is not claimed yet because the
separate pinned BuildKit/go-actions-cache probe has not been added and passed.

The supported upload sequence is:

1. bearer-authenticated Twirp JSON `CreateArtifact`;
2. Azure Block Blob-compatible `Put Block` requests;
3. one Azure `Put Block List` commit;
4. bearer-authenticated Twirp JSON `FinalizeArtifact`.

Published artifacts can be read during the same workflow run through the
official client's Twirp JSON `ListArtifacts` and `GetSignedArtifactURL`
operations. List filters are resolved from PostgreSQL metadata after checking
the active run/job/attempt fence. A returned download URL is a short-lived
capability bound to the exact artifact ID and content SHA-256. The download
handler verifies the canonical manifest and streams its immutable blocks in
order without buffering the complete archive.

The Azure facade exists because the official client constructs an
`@azure/storage-blob` `BlockBlobClient` from the signed upload URL. Blocks are
stored independently through `ImmutableBlobStore`. Finalization verifies the
ordered content SHA-256 without buffering the complete artifact. Before any
block read, PostgreSQL grants one expiring, generation-fenced finalization
claim. The winner renews that bounded claim between object operations and
persists the verified content digest, canonical manifest bytes, and manifest
descriptor before the immutable manifest put. Exact followers never read the
blocks while a claim is live; after expiry they either resume the persisted
manifest publication or take over verification under a newer generation. Only
the current live generation can commit publication, and completed requests are
replayed from the durable winner. No database transaction spans object I/O.
Downloads can later replay the manifest's block order. S3 listing is never used
for coordination.

Runtime JWTs bind the run, job, attempt, and fencing token. Signed upload and
download URLs use separate derived keys and protocol domains. Every metadata
mutation rechecks the durable attempt lifecycle and fence.

The control plane issues that JWT through `GithubResultsRuntimeAuthorityIssuer`
while constructing the exact durable lease offer. Protocol v4 makes the
authority bundle mandatory; the runner stores it as separately authenticated
content before acceptance and injects it only into that job. There is no
runner- or fleet-scoped Results credential.

Production endpoints use `ResultsPublicEndpoint::https`. Local listeners must
opt into either loopback-only development or an exact trusted private bind and
host mapping (for example the Podman bridge gateway plus
`host.containers.internal`). The Results router belongs on that independently
configured listener; wildcard/public plaintext binds are rejected.

Artifact deletion and garbage collection remain future operations behind the
same repository and manifest boundaries. Cache v2 exposes no delete method;
its durable inactivity and quota eviction leave immutable unreferenced objects
for a future bounded object-garbage collector.

Protocol behavior is based on the official
[`actions/toolkit`](https://github.com/actions/toolkit/tree/main/packages/artifact)
artifact client, the pinned
[`actions/cache` 5.0.5](https://github.com/actions/cache/tree/v5.0.5) release,
and Microsoft's
[`Put Block`](https://learn.microsoft.com/rest/api/storageservices/put-block)
and
[`Put Block List`](https://learn.microsoft.com/rest/api/storageservices/put-block-list)
specifications. An ignored integration test runs the actual 6.2.0 client; its
module path is supplied through `AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE`.
