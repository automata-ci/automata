# GitHub Actions Results compatibility

`automata-results-github` implements the artifact upload slice exercised by
`actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`
(v7.0.1, `@actions/artifact` 6.2.0). It is an HTTP adapter around neutral
application, repository, immutable-object, clock, identity, and credential
ports; GitHub protocol types do not leak into the scheduler or runner core.

The supported upload sequence is:

1. bearer-authenticated Twirp JSON `CreateArtifact`;
2. Azure Block Blob-compatible `Put Block` requests;
3. one Azure `Put Block List` commit;
4. bearer-authenticated Twirp JSON `FinalizeArtifact`.

The Azure facade exists because the official client constructs an
`@azure/storage-blob` `BlockBlobClient` from the signed upload URL. Blocks are
stored independently through `ImmutableBlobStore`. Finalization verifies the
ordered content SHA-256 without buffering the complete artifact, publishes a
canonical immutable manifest, then atomically records that descriptor in
PostgreSQL. Downloads can later replay the manifest's block order. S3 listing
is never used for coordination.

Runtime JWTs bind the run, job, attempt, and fencing token. Signed upload URLs
are short-lived per-upload capabilities under a separately derived key. Every
metadata mutation rechecks the durable attempt lifecycle and fence.

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

`ListArtifacts`, `GetSignedArtifactURL`, download streaming, deletion/retention,
and garbage collection are intentionally future operations behind the same
repository and manifest boundaries. The current adapter fails closed for those
unimplemented methods.

Protocol behavior is based on the official
[`actions/toolkit`](https://github.com/actions/toolkit/tree/main/packages/artifact)
client and Microsoft's
[`Put Block`](https://learn.microsoft.com/rest/api/storageservices/put-block)
and
[`Put Block List`](https://learn.microsoft.com/rest/api/storageservices/put-block-list)
specifications. An ignored integration test runs the actual 6.2.0 client; its
module path is supplied through `AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE`.
