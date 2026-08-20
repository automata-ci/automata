# Releasing Automata

Automata publishes releases from `.ci/workflows/release.yml`. GitHub Actions is
not used and should remain disabled for this repository. GitHub provides the
source, Check Runs, release API, and container registry; Automata admits and
executes every release job.

No public version has been published yet. Complete the first-release setup
before pushing a `v*` tag. Normal installation instructions belong in
[Getting started](getting-started.md).

## Release contents

A release of workspace version `X.Y.Z` publishes:

| Destination | Names |
| --- | --- |
| crates.io | Every publishable workspace crate, in dependency order |
| GitHub Release | `automata-x86_64-unknown-linux-musl.tar.gz`, its `.sha256` file, `automata-release-manifest.json`, `automata-local-installation-catalog.json`, and `automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar` |
| GHCR | `ghcr.io/automata-ci/automata:X.Y.Z`, `ghcr.io/automata-ci/automata-runner:X.Y.Z`, and `ghcr.io/automata-ci/automata-sandbox-guest:X.Y.Z` |
| Stable aliases | The three GHCR images also receive `latest` for a stable version |

The Linux archive contains `automata`, `automata-runner`, license and
third-party notices, SBOMs, a version record, and internal checksums. Its stable
filename supports GitHub's `latest/download` URL; the release tag supplies the
version boundary.

The native workflow does not publish GitHub artifact attestations. GitHub's
attestation service accepts GitHub Actions identity, while the deployed
Automata workload-OIDC endpoint is not enabled. Release files carry SHA-256
checksums and the images carry generated SBOMs, but those records are not signed
provenance. Add Automata-native signing only after its issuer and a public
verifier have production acceptance evidence.

## First-release setup

You need repository administration, access to the Automata GitHub App, a
crates.io owner account, and a scoped crates.io API token. Do not create the tag
until every item below passes.

### Grant the Automata App publication permissions

The installed `automata-ci` GitHub App must have these repository permissions:

- Checks: read and write;
- Contents: read and write; and
- Packages: read and write.

Contents permission creates the draft, uploads assets, and publishes the
release. Packages permission pushes GHCR images and moves stable aliases. After
changing the App, an organization owner must accept the new installation
permissions. Confirm the live installation before tagging; the workflow fails
closed when Automata cannot mint its job-scoped `github.token`.

Keep GitHub Actions disabled under **Settings → Actions → General**. Enabling it
does not help this workflow and creates a second execution authority the
repository does not use.

### Configure Automata-managed secrets

The release workflow does not use deployment environments because that syntax
is unsupported by Automata. A human-created, protected tag authorizes the run;
Automata's trust policy admits managed secrets only for the same-repository tag
event.

Log in to `https://ci.automata-ci.com`, activate the built-in secret provider,
and create three repository-scoped secrets:

```console
automata secret --server-url https://ci.automata-ci.com provider status
automata secret --server-url https://ci.automata-ci.com provider activate

automata secret --server-url https://ci.automata-ci.com create \
  CRATES_IO_EXPECTED_OWNER_LOGINS \
  --scope repo:automata-ci/automata \
  --from-file /absolute/path/to/crates-owner-logins
automata secret --server-url https://ci.automata-ci.com create \
  CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED \
  --scope repo:automata-ci/automata \
  --from-file /absolute/path/to/crates-burst-approval
automata secret --server-url https://ci.automata-ci.com create \
  CARGO_REGISTRY_TOKEN \
  --scope repo:automata-ci/automata \
  --from-file /absolute/path/to/crates-token
```

Each input file must be an absolute, non-symlink path owned by the caller with
mode `0400` or `0600`. The owner file contains the sorted, comma-separated
crates.io login set that must own every Automata crate. The approval file
contains `true` only after crates.io support approves the initial name burst.
The token file contains a narrowly scoped crates.io API token.

List secret metadata after creation; values are never returned:

```console
automata secret --server-url https://ci.automata-ci.com list \
  --scope repo:automata-ci/automata
```

The gate receives the owner and burst values for its read-only crates.io check.
Only the isolated `publish_crates` job receives `CARGO_REGISTRY_TOKEN`. That job
does not check out the repository or run Cargo. It downloads same-run,
digest-bound artifacts and sends the prepared `.crate` bytes with the bounded
registry client in `scripts/ci/publish-crates.py`.

Managed-secret delivery remains an experimental Automata capability. Verify
provider readiness and a non-production same-repository workflow before relying
on it for the first irreversible publication.

### Obtain crates.io capacity

Trusted Publishing on crates.io accepts GitHub Actions OIDC and cannot
authenticate an Automata job. Use the scoped API token for native releases;
rotate it after the first release and whenever the owner set changes.

The workspace has 54 unpublished crate names. Ask crates.io support for a
temporary new-crate rate-limit override for the publishing account and the full
name set. After approval, put `true` in the burst-approval managed secret.

Run this read-only preflight immediately before tagging:

```console
export CRATES_IO_EXPECTED_OWNER_LOGINS='approved-crates-io-login'
export CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED=true
./scripts/ci/publish-crates.py --check-capacity
```

Replace the placeholder with the exact crates.io login. Expected output before
the first release is `54 new, 0 owned`. A claimed name with a different owner is
a hard stop. The workflow repeats the check before mutation and before each new
name.

crates.io publication is permanent: a version cannot be overwritten or
deleted. Recovery accepts an existing version only when its public checksum
matches the prepared archive exactly.

### Protect tags and releases

Create a repository ruleset for `refs/tags/v*` that restricts creation, update,
and deletion to release maintainers. Enable immutable releases under
**Settings → General → Releases** before the first tag.

The workflow also rejects a lightweight tag, a moved tag, an existing public
release, and a tag name that differs from `v` plus the workspace version.

### Plan the first GHCR visibility change

Automata's Buildx and BuildKit path is experimental: its closed Docker API is
implemented and locally tested, but the production runner has not completed the
repository's live Buildx acceptance fixture. The release stage bootstraps the
native BuildKit boundary before it creates a draft or changes a registry. Do
not treat a queued job as proof that the runner has this capability; require a
successful bootstrap in the release run before investigating any publication
state.

GitHub normally creates new organization packages as private. The first staging
attempt can push the three versioned images and then stop at anonymous-read
verification. If that happens:

1. Leave the tag, draft, and image tags unchanged.
2. Change `automata`, `automata-runner`, and `automata-sandbox-guest` to public
   in the organization package settings.
3. Verify each versioned image without logging in.
4. Rerun the failed Automata jobs for the same release run.

The workflow reconciles the existing draft and digest-bound images before
reaching crates.io. Do not publish crates until every image is anonymously
readable.

## Prepare a release commit

Work from a clean branch based on `main`.

1. Set one workspace version without SemVer build metadata.
2. Add a `CHANGELOG.md` heading in the form `## [X.Y.Z] - YYYY-MM-DD`.
3. Set the `[Unreleased]` comparison link to start at `vX.Y.Z` and add the exact
   `vX.Y.Z` release link.
4. Run the local rehearsal and the normal test suite.
5. Merge through the repository's merge queue and wait for
   `Automata CI / .ci/workflows/ci.yml` to succeed on the resulting commit.

Before any mutation, the release gate requires the tagged commit to be in
`main` and queries GitHub for one latest Check with all of these properties:

- App ID `4558711`, slug `automata-ci`, and organization owner `automata-ci`;
- check name `Automata CI / .ci/workflows/ci.yml`;
- the exact tagged commit and a successful terminal conclusion;
- an `automata-check:<UUID>` external identity; and
- the `https://ci.automata-ci.com/automata-ci/automata/actions` dashboard path.

The gate also requires GitHub's merge base for `TAG_COMMIT...main` to equal the
tagged commit. A same-name Check from another App, success on another SHA, or a
tag outside `main` cannot authorize publication.

## Publish

Create and push one annotated tag from the reviewed release commit:

```console
version="$(./scripts/ci/workspace-version.sh)"
git status --short
git tag --annotate "v${version}" --message "Automata ${version}"
git push origin "v${version}"
```

`git status --short` must print nothing. The tag push starts the Release run in
the [Automata dashboard](https://ci.automata-ci.com/automata-ci/automata/actions).
The gate performs only reads. Staging starts after the tag, version, changelog,
release order, main ancestry, trusted CI Check, and crates.io capacity all pass.

The workflow then:

1. packages all crates and builds the static Linux executables;
2. verifies ELF linkage and executable version provenance without a nested
   container runtime;
3. generates SBOMs, notices, the archive, checksum, service-proxy candidate,
   installation catalog, and release manifest;
4. creates or reconciles the exact draft GitHub Release;
5. builds and pushes three digest-addressed images through Automata's BuildKit
   boundary and checks anonymous access;
6. transfers the release handoff and crate plan through Automata's same-run
   artifact service with producer and service digests;
7. publishes or verifies each crate in dependency order;
8. verifies every crates.io checksum and owner set;
9. moves `latest` for a stable version; and
10. rechecks the remote tag, release order, draft bytes, and images before
    making the GitHub Release public.

The service-proxy candidate uses Buildah chroot isolation and metadata-only
image verification because nested Podman and Docker loading are unavailable in
an Automata job. The static executable check supplies its process test. A
prerelease version creates a GitHub prerelease and does not move `latest`.

## Recover a failed run

Never move or recreate the tag. Use Automata's authenticated rerun command for
the same public run identity:

```console
automata rerun --server-url https://ci.automata-ci.com \
  automata-ci/automata RUN_UUID \
  --selection failed-jobs-and-dependents --output json
```

Replace `RUN_UUID` with the release run UUID from the dashboard. Every rerun
rechecks the immutable tag and current external state.

Recovery accepts only the workflow's bounded draft asset prefixes,
digest-matching images, and exact crate checksums. It compares a recovered
service-proxy candidate byte for byte and validates the catalog and manifest
against the release identity and recorded image digests. The catalog is not
cryptographically signed; repository write access remains inside this recovery
trust boundary until Automata-native signing is available.

Unexpected assets, changed bytes, a different image digest, a moved tag, a
changed owner set, or a crate checksum mismatch stops the run. If the tagged
source is wrong, prepare a new patch version. Do not reuse the version.

The three `latest` updates are sequential. A failure can temporarily leave one
alias ahead of another. Rerun finalization to reapply and verify all three exact
digests; use version tags as the release-completeness signal.

## Verify a public release

Run these checks without registry credentials:

```console
version="$(./scripts/ci/workspace-version.sh)"

gh release view "v${version}" --repo automata-ci/automata
curl --fail --location \
  "https://github.com/automata-ci/automata/releases/download/v${version}/automata-x86_64-unknown-linux-musl.tar.gz.sha256"
curl --fail --location --output automata-local-installation-catalog.json \
  "https://github.com/automata-ci/automata/releases/download/v${version}/automata-local-installation-catalog.json"
cargo search automata-ci --limit 1
podman manifest inspect "ghcr.io/automata-ci/automata:${version}" >/dev/null
podman manifest inspect "ghcr.io/automata-ci/automata-runner:${version}" >/dev/null
podman manifest inspect \
  "ghcr.io/automata-ci/automata-sandbox-guest:${version}" >/dev/null
```

Download the archive and verify its `.sha256` file. Install it in a disposable
x86-64 Linux account or container, then confirm both `--version` outputs and
both top-level `--help` responses. Test a complete server deployment separately
with its required PostgreSQL, object storage, Results, runner mTLS, and provider
configuration, and check `/healthz` and `/readyz`. Do not test a release by
overwriting a production installation before the disposable verification
passes.

## Rehearse without publishing

The local rehearsal writes only under `target/` and does not contact a registry:

```console
export AUTOMATA_EXPECTED_VERSION="$(./scripts/ci/workspace-version.sh)"
export AUTOMATA_EXPECTED_GIT_SHA="$(git rev-parse --verify 'HEAD^{commit}')"
export AUTOMATA_BUILD_GIT_SHA="$AUTOMATA_EXPECTED_GIT_SHA"
export AUTOMATA_RELEASE_CREATED="$(git show -s --format=%cI HEAD)"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"

./scripts/ci/build-static-musl.sh
AUTOMATA_SCRATCH_RUNTIME=none ./scripts/ci/verify-static-musl.sh
./scripts/ci/verify-sandbox-guest-static.sh
./scripts/ci/verify-service-proxy-static.sh
./scripts/ci/generate-sboms.sh
./scripts/ci/prepare-third-party-license-sources.sh
./scripts/ci/generate-third-party-licenses.sh
./scripts/ci/package-static-musl.sh
bash scripts/ci/tests/install.test.sh
bash scripts/ci/tests/container-context.test.sh
```

See [Development](development.md#static-linux-distribution) for the required
Rust, musl, ELF, Buildah, Node.js, and SBOM tooling.
