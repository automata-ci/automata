# GitHub Actions Results compatibility

`automata-ci-results-github` implements the Results protocols currently needed
by Automata jobs. It is an HTTP adapter around provider-neutral application,
repository, object-storage, clock, identity, and credential ports. GitHub wire
types do not enter the scheduler or runner core.

The implemented clients are:

- `actions/upload-artifact` v7.0.1 at commit
  `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`, using `@actions/artifact`
  6.2.0; and
- `actions/cache` 5.0.5 using JSON Twirp CacheService v2.

These are tested protocol slices, not general artifact or cache API
compatibility.

## Artifacts

The upload sequence is:

1. bearer-authenticated Twirp JSON `CreateArtifact`;
2. Azure Block Blob-compatible `Put Block` requests;
3. one Azure `Put Block List` commit; and
4. bearer-authenticated Twirp JSON `FinalizeArtifact`.

The Azure facade exists because the official client constructs an
`@azure/storage-blob` `BlockBlobClient` from the signed upload URL. Blocks are
stored independently through `ImmutableBlobStore`.

Finalization claims one expiring generation in PostgreSQL, verifies the ordered
content SHA-256 without buffering the archive, and persists the canonical
manifest. A current winner renews the claim between object reads. A follower
waits while that claim is live; after expiry it can resume manifest publication
or verify under a newer generation. Only the live generation may commit. No
database transaction spans object I/O, and object-store listing is never used
for coordination.

Within the same workflow run, the official client can use `ListArtifacts` and
`GetSignedArtifactURL`. List filters resolve against PostgreSQL after the
run/job/attempt fence is checked. A download URL is a short-lived capability
for one artifact ID and content digest. The handler verifies the manifest and
streams blocks in order.

Cross-run artifact management, deletion, retention, and garbage collection are
not implemented.

## CacheService v2

The adapter implements `CreateCacheEntry`, `FinalizeCacheEntryUpload`, and
`GetCacheEntryDownloadURL`. It accepts protobuf field names and decimal strings
for protobuf `int64` values; compatible numeric requests are also accepted.

The runner sets `ACTIONS_CACHE_SERVICE_V2=true` only when the Results service
is composed, then injects the same short-lived `ACTIONS_RUNTIME_TOKEN` used for
authentication.

Cache JWTs contain an authenticated repository and bounded `ac` scopes. The
server derives the first scope from current JobIR evidence; a request cannot
widen it. Push refs and canonical pull-request merge refs may write. Other
events remain read-only unless their write safety is proven.

Lookup order is:

1. the current ref;
2. the distinct canonical default branch from server-owned repository metadata.

The default branch is always read-only. Within each readable ref, lookup checks
the exact primary key, primary prefix, then ordered restore prefixes, choosing
the newest finalized match. Entries are immutable and scoped by repository,
ref, key, and version. Reads may cross workflow runs inside the same repository;
repository or unlisted-ref mismatches do not authorize a read.

PostgreSQL owns fencing, block-list commits, last access, seven-day inactivity
retention, and a 10 GiB per-repository quota with LRU eviction. Signed downloads
support `HEAD`, full `GET`, and one byte range with `206` and `416` behavior.
Eviction currently leaves unreferenced immutable objects for a future bounded
collector. There is no cache management or delete API.

The bounded Buildx/BuildKit session and provenance surface is implemented, but
cache interoperability is not yet production-proven. Live CacheService v2
acceptance still needs its own pinned BuildKit fixture.

## Runtime authority and listener policy

Runtime JWTs bind the run, job, attempt, and fencing token. Upload and download
URLs use separate protocol domains and derived keys. Every metadata mutation
rechecks the attempt lifecycle and fence.

`GithubResultsRuntimeAuthorityIssuer` creates the JWT while building the
durable lease offer. Runner protocol v4 requires the authority bundle. The
runner stores it as separately authenticated content and injects it into that
job only; there is no runner- or fleet-wide Results credential.

Production uses an HTTPS public Results endpoint. Development may use literal
loopback HTTP or one exact trusted private bind and host mapping, such as a
Podman bridge gateway with `host.containers.internal`. Wildcard and public
plaintext binds are rejected. The Results router stays on its dedicated
listener.

## Evidence

The protocol implementation follows the official
[`actions/toolkit`](https://github.com/actions/toolkit/tree/main/packages/artifact)
artifact client, the pinned
[`actions/cache` 5.0.5](https://github.com/actions/cache/tree/v5.0.5) release,
and Microsoft's
[`Put Block`](https://learn.microsoft.com/rest/api/storageservices/put-block)
and
[`Put Block List`](https://learn.microsoft.com/rest/api/storageservices/put-block-list)
specifications.

Ignored offline integration tests run the exact artifact and cache clients when
their module paths are supplied through
`AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE` and
`AUTOMATA_TEST_ACTIONS_CACHE_MODULE`. The tests download no packages.
