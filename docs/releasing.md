# Releasing Automata

This document records Automata's intended public-release contract and the
local, non-publishing preparation paths that remain safe to run. Normal users
should follow [getting started](getting-started.md).

> [!CAUTION]
> Automated public publication is currently disabled. `release.yml`,
> `profile-image.yml`, and `service-proxy-image.yml` fail before checkout or
> mutation. Automata Check Runs do not yet expose one provider-authenticated
> record binding the trusted provider App and dashboard origin, exact
> repository, commit, `.ci/workflows/ci.yml`, push event, `refs/heads/main`,
> logical distribution job, workflow run, and job attempt. GitHub's hosted
> attestation and protected-environment identities also
> cannot authenticate a self-hosted Automata job. Do not treat a same-name
> Check, a repository variable, or a GitHub-hosted signer claim as authority.
> The setup and publication sequence below is a target design, not an enabled
> operator procedure.

## Intended publication contract

Once native authority and an accepted Automata attestation verifier exist,
workspace version `X.Y.Z` is intended to publish:

| Destination | Published names |
| --- | --- |
| crates.io | Every publishable workspace package in dependency order, including `automata-ci` and `automata-ci-runner` |
| GitHub Release | `automata-x86_64-unknown-linux-musl.tar.gz`, its `.sha256` file, `automata-release-manifest.json`, `automata-local-installation-catalog.json`, and `automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar` |
| GHCR | `ghcr.io/automata-ci/automata:X.Y.Z`, `ghcr.io/automata-ci/automata-runner:X.Y.Z`, and `ghcr.io/automata-ci/automata-sandbox-guest:X.Y.Z` |
| Stable aliases | All three GHCR images also receive `latest` for a non-prerelease version |
| Attestations | The release archive and checksum, local-installation catalog, service-proxy candidate, and provenance and SBOM statements for all three images |

The archive contains `automata`, `automata-runner`, the license, third-party
notices, SBOMs, a version file, and internal checksums. The filename stays
stable across versions so the installer can use GitHub's `latest/download` URL;
the release tag supplies the version boundary.

## One-time repository setup

Do not perform this setup merely to bypass the disabled workflows. These are
future enablement requirements after the missing authority surfaces are
implemented and reviewed.

### 1. Create the protected publication environments

In **Settings → Environments**, create environments named `release`,
`crates-io`, and `profile-promotion`. These target settings do not enable the
disabled workflows. Allow `release` and `crates-io` deployments from the
protected default branch and tags matching the repository's `v*` convention.
Keep `release` as the unattended staging boundary without required reviewers.
On `crates-io`, add at least one required reviewer and prevent self-review
because it authorizes irreversible package publication. GitHub Actions manual
dispatch is not an authorized publication or retry path. Future recovery must
use an authenticated Automata dispatch bound to the exact immutable release
identity and original authority evidence.

Restrict `profile-promotion` to the protected default branch only, add a
required reviewer, and prevent self-review. It authorizes only promotion of an
already reviewed runner-profile digest. Environment secrets are not available
to a job until its protection rules pass; see
[GitHub's environment documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

### 2. Add the one-time crates.io bootstrap token

Trusted Publishing cannot create a crate's first release. For the first Automata
release, create a tightly scoped crates.io API token and add it only to the
`crates-io` environment as `CARGO_REGISTRY_TOKEN`. Leave the
`CRATES_IO_TRUSTED_PUBLISHING` variable unset. The token must be allowed to
reserve and publish every package in the `automata-ci-*` workspace.

Treat this as a production credential. Do not store it as a repository file,
shell argument, workflow input, or general repository variable. crates.io
publication is permanent—the same name and version cannot be overwritten—so
review [Cargo's publishing contract](https://doc.rust-lang.org/cargo/reference/publishing.html)
before creating the first tag.

After the first release succeeds, a future publication design may configure a
trusted publisher accepted for Automata's actual issuer and restricted to this
repository, `release.yml`, and the `crates-io` environment. It must not claim a
GitHub-hosted Actions identity for an Automata job. Only after that issuer is
accepted may an operator set `CRATES_IO_TRUSTED_PUBLISHING=true`, delete the
bootstrap secret, and revoke the token on crates.io. The crates.io team
documents both the
[first-release requirement](https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07/)
and the [official authentication action](https://github.com/rust-lang/crates-io-auth-action).

Before creating the first tag, set the repository variable
`CRATES_IO_EXPECTED_OWNER_LOGINS` to the sorted, comma-separated crates.io
logins that must exactly own any already-claimed Automata name. Crate names are
[first come, first served](https://doc.rust-lang.org/cargo/reference/publishing.html#before-publishing-a-new-crate),
so the future gate must check every workspace name before any staging mutation
and repeat the owner audit immediately before the first upload.

The workspace currently needs far more new names than crates.io's normal burst
of five; the standard limit then permits only one new crate every ten minutes.
Obtain a temporary initial-publish override for the exact bootstrap account from
crates.io support before tagging, following the
[official rate-limit guidance](https://crates.io/docs/rate-limits). Only after
written confirmation, set the repository variable
`CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED=true`. Remove it after the initial
names are claimed. Once publication is enabled, missing confirmation must fail
in a read-only gate before drafts, images, attestations, or packages are
created.
Repeat the same live check immediately before tagging:

```console
export CRATES_IO_EXPECTED_OWNER_LOGINS='approved-owner'
export CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED=true
./scripts/ci/publish-crates.py --check-capacity
```

Replace `approved-owner` with the exact configured allowlist. Name availability
can change after any check; the credentialed executor therefore checks again
before its first PUT and before claiming each name.

### 3. Confirm workflow permissions

Repository and organization Actions policy must allow the job's declared
permissions:

- the staging job receives `contents`, `packages`, `id-token`, `attestations`,
  and `artifact-metadata` write access for the draft, GHCR, and provenance;
- the credential-free crate preparation job receives only `contents: read`;
- the isolated crates.io job receives only `contents: read` and
  `id-token: write`; and
- finalization receives only `contents: write` and `packages: write`, with no
  environment secrets or OIDC permission.

The target workflow uses a short-lived, issuer-appropriate registry token; it
must not reuse GitHub-hosted identity claims for an Automata job or require a
stored general-purpose registry password.

GitHub's `id-token` permission is job-wide rather than step-scoped. The
`crates-io` job therefore checks out no repository and runs no build or
dependency command. Before the explicit crates.io authentication action, it
runs only pinned artifact-download code, fixed runner clients, bounded
materialization, and the closed release-helper module set from a same-run raw
tool bundle selected by artifact ID and verified against both the
artifact-service digest and the preparation-job SHA-256. Those helpers and
their exact catalog, profile, Containerfile, license, and workspace-version
inputs are part of the audited credential-bound trusted code; changes to them
require the same review as the workflow itself.

### 4. Enable private security reporting and dependency alerts

Before making the repository public, enable **Private vulnerability reporting**
under **Settings → Security → Code security and analysis**. Confirm that the
private report link in [SECURITY.md](../SECURITY.md) opens for a logged-in test
account. Enable the dependency graph, Dependabot alerts, and Dependabot security
updates in the same settings area. The checked-in `.github/dependabot.yml`
enables scheduled version-update pull requests; repository settings still
control alerts and security updates.

### 5. Plan the first GHCR visibility change

New organization container packages are private by default. After a future
authorized workflow first pushes `automata`, `automata-runner`, and
`automata-sandbox-guest`, an organization owner or package administrator must
change all three packages to **Public** under their package settings. Public
Container Registry packages can then be pulled anonymously; GitHub documents
the irreversible visibility change in
[Configuring package access and visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

The future sequence must test anonymous manifest access before publishing any
permanent crate version. Publication retry is unavailable while the refusal is
present. After authenticated Automata dispatch exists, it may resume the same
immutable tag only after rebinding the original authority evidence; GitHub
Actions manual dispatch is not an alternative. Do not create a new version
merely to complete this one-time visibility step.

### 6. Protect the release identity

Use a repository ruleset to restrict creation, update, and deletion of `v*` tags
to release maintainers. Enable GitHub's
[immutable releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases)
before the first public tag. The future gate must refuse moved tags and
published releases; the repository settings enforce the same boundary outside
the workflow even while publication is disabled.

## Publish the runner profile

`.ci/workflows/profile-image.yml` is disabled because its GitHub attestation
verification would reject self-hosted evidence and accepting a GitHub-hosted
identity would be false. An operator may still build and inspect a local,
unpublished candidate without registry credentials:

```console
./images/github-hosted-ubuntu-24.04-x64/build-profile.sh
./images/github-hosted-ubuntu-24.04-x64/verify-profile-image.sh \
  ghcr.io/automata-ci/automata-ubuntu-24.04-x64:profile-build
```

The reported local storage digest is not a registry digest. A separately
authorized operator may transfer an already reviewed OCI image with
least-privilege registry credentials, capture the registry-returned digest,
pull that exact digest, and rerun the verifier. That manual transfer is an
out-of-band operator action, not Automata provenance and not permission to move
`profile-v1` or `latest`. Lock or stable-tag changes still require independent
review of the exact remote digest and source commit. The detailed local contract
is in the [profile guide](../images/github-hosted-ubuntu-24.04-x64/README.md).

## Prepare a service-proxy candidate

`.ci/workflows/service-proxy-image.yml` is disabled for the same issuer
mismatch. The credential-free path below mirrors the service-proxy artifact and
policy checks in ordinary CI while retaining the manual and release default:
Podman plus the required live process probe. It requires the pinned Rust
toolchain, `binutils`, musl tools, Podman, Node.js 24.19.0 with npm 11.17.0, and
`cargo-cyclonedx` 0.5.9; see the
[development prerequisites](development.md#static-linux-distribution).

The ordinary native CI `dist_build` job instead explicitly selects the
`buildah-chroot` backend and `metadata-only` image verification. Nested Automata
jobs cannot create the additional namespaces needed by Podman, so that backend
uses Buildah's chroot isolation and host network. A fail-closed validator admits
only the reviewed `FROM scratch`, metadata, local `COPY`, user, working-directory,
and entrypoint instructions; it rejects executable or remote-input instructions
before Buildah starts. The earlier static-binary check supplies the process
contract. Buildah still inspects the image metadata, and
`service-proxy-candidate.py` still validates the exported OCI descriptors,
configuration, source bindings, and candidate provenance before the subsequent
`prepare-candidate` policy gate accepts it.

The canonical candidate retains one deterministic local reference on the sole
OCI index descriptor:
`automata.local/automata-ci-service-proxy:manifest-<manifest-sha256>`.
Ordinary CI, release staging, and the dedicated promotion workflow load the
completed candidate into Docker and prove that this tag creates the matching
immutable image before removing it again. The loader derives a bounded Docker
save transport from the validated OCI manifest, config, layers, and rootfs
diff IDs so both classic and containerd-backed Engine stores are supported.
The imported tag must resolve to exactly the OCI manifest ID or config ID;
containerd-backed stores additionally expose the matching
`automata.local/automata-ci-service-proxy@sha256:<manifest>` identity, while
classic stores do not synthesize a repository digest. The manifest digest
remains the source-image authority; the tag is the closed local import name.

Every image and publication validator requires the sole current
`io.automata.service-proxy.protocol-version=2` capability. Protocol 1 images
predate the Results mode and cannot be admitted or promoted by this path.

Reproducibility comparisons are backend-local: CI compares two Buildah outputs,
while the manual and release paths compare Podman outputs. Both backends produce
OCI candidates accepted by the same validators, but their output bytes are not
claimed to match each other.

Run it from a clean checkout where the four named `target/` output directories
do not already exist:

```console
export AUTOMATA_EXPECTED_VERSION="$(./scripts/ci/workspace-version.sh)"
export AUTOMATA_EXPECTED_GIT_SHA="$(git rev-parse --verify 'HEAD^{commit}')"
export AUTOMATA_BUILD_GIT_SHA="$AUTOMATA_EXPECTED_GIT_SHA"
export AUTOMATA_RELEASE_CREATED="$(git show -s --format=%cI HEAD)"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"

./scripts/ci/build-static-musl.sh
AUTOMATA_SCRATCH_RUNTIME=podman ./scripts/ci/verify-static-musl.sh
./scripts/ci/verify-service-proxy-static.sh
./scripts/ci/generate-sboms.sh
./scripts/ci/prepare-third-party-license-sources.sh
./scripts/ci/generate-third-party-licenses.sh
./scripts/ci/generate-third-party-licenses.sh \
  target/third-party-license-reproduction
diff --recursive --brief \
  target/distribution-input/licenses \
  target/third-party-license-reproduction

./scripts/ci/prepare-service-proxy-context.sh \
  target/service-proxy-context \
  "$AUTOMATA_EXPECTED_VERSION" \
  "$AUTOMATA_EXPECTED_GIT_SHA" \
  "$AUTOMATA_RELEASE_CREATED" \
  "$SOURCE_DATE_EPOCH"
AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME=podman \
  ./scripts/ci/build-service-proxy-candidate.sh \
    target/service-proxy-context \
    target/service-proxy-publication
AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME=podman \
  ./scripts/ci/build-service-proxy-candidate.sh \
    target/service-proxy-context \
    target/service-proxy-publication-reproduction
cmp -- \
  target/service-proxy-publication/automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar \
  target/service-proxy-publication-reproduction/automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar

python3 scripts/ci/service-proxy-publication.py prepare-candidate \
  --candidate target/service-proxy-publication/automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar \
  --source-directory . \
  --candidate-commit "$AUTOMATA_EXPECTED_GIT_SHA" \
  --publisher-commit "$AUTOMATA_EXPECTED_GIT_SHA" \
  --run-id 1 \
  --run-attempt 1 \
  --output target/service-proxy-policy-review
sha256sum \
  target/service-proxy-policy-review/automata-service-proxy.oci.tar
```

The context command's five arguments are, in order, the output context,
workspace version, exact source revision, canonical commit timestamp, and that
timestamp as Unix seconds. The SBOM and both third-party license files are
mandatory context inputs. Local run ID and attempt `1` are positive identifiers
used only to make the review metadata well formed; they do not claim a hosted
workflow identity. `prepare-candidate` applies the same trusted publisher policy
as ordinary CI and extracts the reviewed OCI bytes. The operator handoff is
`target/service-proxy-policy-review/automata-service-proxy.oci.tar`; the outer
`automata-service-proxy-candidate-*.tar` is the reproducible policy input, not
the image-registry upload artifact. A release also retains that outer candidate
as the byte-exact local-installation payload named by its catalog. Review the
adjacent proposed lock, source identity, source provenance, and SBOM together
with the OCI archive. These steps write only below `target/`; they do not push
an image, bind a tag, or create an attestation.

A separately authorized operator may upload only the reviewed OCI archive and
must capture and anonymously re-read the registry digest before proposing a
lock change. Stable `v1` and `latest` tags remain disabled until a verifier can
authenticate an Automata-issued statement binding the publisher commit,
`.ci/workflows/service-proxy-image.yml`, an authenticated Automata dispatch,
the main ref, the candidate source commit, source-provenance digest, and exact
image digest.

## Local-installation release catalog

`images/local-installation/catalog-v1.json` is the reviewed source contract for
one Unix-hosted, `linux/amd64` installation. Its role set is closed to exactly
Automata, runner, sandbox guest, service proxy, PostgreSQL, RustFS, and the
GitHub-hosted Ubuntu 24.04 x64 compatibility profile. The release workflow
resolves the three first-party images produced by that release, retains the
protocol 2 service-proxy OCI candidate, and qualifies each fixed third-party or
profile image with its top-level, platform-manifest, and configuration digests.
The emitted catalog also binds the exact profile manifest and lock bytes.

The catalog is declarative release evidence. It does not materialize engine
objects, install or bootstrap a runner, mint credentials, select secrets, or
add a relay or generic image-fetch API. A later installation implementation
must consume this closed schema in its own reviewed slice and still prove the
downloaded assets and registry content against these bindings.

## Prepare a release

1. Update `[workspace.package].version` in the root `Cargo.toml`.
2. Refresh `Cargo.lock` with the pinned toolchain and commit the result.
3. Move the version's entries from `[Unreleased]` into a version heading in
   [CHANGELOG.md](../CHANGELOG.md) with the release date in `YYYY-MM-DD` form.
   Add the version's exact `/releases/tag/vVERSION` link and change the
   `[Unreleased]` link to `/compare/vVERSION...HEAD`; the release gate requires
   both exact links, while ordinary CI permits a truthful pre-tag changelog.
4. Update compatibility status, user documentation, and release-relevant
   fixtures for the version.
5. Run the normal CI checks and the package preflight.

From a clean repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
mapfile -t publishable_crates < <(
  python3 scripts/ci/publish-crates.py --list-publishable
)
(( ${#publishable_crates[@]} > 0 ))
package_arguments=()
for crate in "${publishable_crates[@]}"; do
  package_arguments+=(--package "$crate")
done
cargo package --locked "${package_arguments[@]}"
./scripts/ci/publish-crates.py
```

With no arguments, the final command is read-only: it verifies every packaged
README and byte-exact license, computes archive checksums, checks every intended
crates.io version before any upload, and prints the dependency-ordered
publication plan.

Review the release commit while it is still untagged. In particular, confirm:

- the workspace and lockfile report exactly one intended version;
- CI passes at that exact commit;
- every publishable workspace package can be packaged;
- the compatibility document makes no unsupported claim; and
- no generated archive, credential, or scratch file is staged.

Every publishable crate carries a physical `LICENSE` file whose bytes must
match the repository-root MIT license. This keeps Cargo's standard
`license = "MIT"` SPDX metadata without the warnings produced by setting both
`license` and `license-file`. The product-target check validates all source
copies, and the publication preflight rejects a missing, changed, or symbolic
archive entry before contacting crates.io.

Workspace members with `publish = false` are intentionally absent from the
crate archives, release handoff, and publication plan. The preflight derives
one dependency-ordered publishable set from locked Cargo metadata and fails if
any publishable crate has a non-development dependency on a private workspace
member; the release workflow packages only that emitted set.

## Tag and publish

Do not push a release tag expecting publication while the fail-closed gate is
present. A tag push starts a deliberately failing gate and no staging or
publication job receives authority. The commands and sequence below describe
the future reviewed procedure after native release evidence is implemented.

Create one annotated tag whose name exactly matches the workspace version. The
future gate must retain and revalidate both the tag object and its peeled
commit, so a lightweight replacement or a newly annotated object at the same
commit fails:

```console
version="$(./scripts/ci/workspace-version.sh)"
git status --short
git tag --annotate "v${version}" --message "Automata ${version}"
git push origin "v${version}"
```

Only tag a reviewed release commit. After authority is implemented, the gate
must reject a tag that does not equal `v` plus the workspace version, a
mismatched checkout, or a dirty release build.

When enabled, the tag push starts `.ci/workflows/release.yml`. Every version
shares one repository-wide publication lock, so crates.io publication and the
three global `latest` aliases cannot race another release. A different
unfinished draft blocks the next tag, and a stable version must be newer than
every stable GitHub Release already published. The future pipeline must perform
these gates in order:

1. prove, before mutation, that the tag commit is an ancestor of current `main`
   and that exact provider-authenticated Automata CI authority passed for that
   SHA;
2. stage every crate and exercise the two distribution executables and both
   fixed helper executables as static musl binaries inside the protected
   `release` environment;
3. generate SBOMs, license material, the deterministic archive and checksum,
   the release-scoped service-proxy candidate, the closed local-installation
   catalog, and the canonical release manifest;
4. create or recover the exact draft, verify and attest its accepted bytes, and
   bind the three release-image digests before creating version tags;
5. transfer the bounded payload, publication plan, and minimal release-helper
   bundle through same-run raw artifacts selected by numeric ID and checked
   against both service and producer digests;
6. repackage every crate without OIDC permission, require a byte-for-byte match
   to the handoff, derive bounded registry metadata from each normalized
   manifest, and revalidate the tag, draft bytes, release order, and images;
7. enter the separate `crates-io` environment, repeat the live identity and
   owner checks, and send each missing digest-bound `.crate` byte stream through
   the official length-prefixed crates.io API in dependency order;
8. verify every exact non-yanked crates.io version and its owner set before any
   mutable alias changes;
9. move all three GHCR `latest` aliases only for a stable release and verify
   them; and
10. revalidate the remote tag, release order, version images, and draft bytes in
    the last pre-publication window, then make the GitHub Release public without
    OIDC credentials.

Versions containing a prerelease suffix publish as GitHub prereleases and do
not move any GHCR `latest` tag.

## Verify the published release

For a non-prerelease, verify every public installation surface without registry
credentials:

```console
version="$(./scripts/ci/workspace-version.sh)"
release_commit="$(git rev-parse "v${version}^{commit}")"

curl --fail --location \
  "https://github.com/automata-ci/automata/releases/download/v${version}/automata-x86_64-unknown-linux-musl.tar.gz.sha256"
curl --fail --location --output automata-local-installation-catalog.json \
  "https://github.com/automata-ci/automata/releases/download/v${version}/automata-local-installation-catalog.json"
curl --fail --location \
  --output automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar \
  "https://github.com/automata-ci/automata/releases/download/v${version}/automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar"
gh attestation verify automata-local-installation-catalog.json \
  --repo automata-ci/automata \
  --signer-workflow automata-ci/automata/.ci/workflows/release.yml \
  --source-ref "refs/tags/v${version}" \
  --source-digest "$release_commit" \
  --deny-self-hosted-runners
gh attestation verify \
  automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar \
  --repo automata-ci/automata \
  --signer-workflow automata-ci/automata/.ci/workflows/release.yml \
  --source-ref "refs/tags/v${version}" \
  --source-digest "$release_commit" \
  --deny-self-hosted-runners
cargo search automata-ci --limit 1
podman manifest inspect "ghcr.io/automata-ci/automata:${version}" >/dev/null
podman manifest inspect "ghcr.io/automata-ci/automata-runner:${version}" >/dev/null
podman manifest inspect \
  "ghcr.io/automata-ci/automata-sandbox-guest:${version}" >/dev/null
```

Test the installer on a disposable x86-64 Linux account or container, confirm
both `--version` outputs, start `automata preview`, and check `/healthz` and
`/readyz`. Do not test a release by overwriting a production installation
before the disposable verification passes.

## Retry and failure behavior

Publication retry is unavailable while the fail-closed refusal is present.
GitHub Actions **Run workflow**, rerun, and `workflow_dispatch` are not trusted
release authority and cannot bypass it. A future retry may resume the same
immutable tag only through an authenticated Automata dispatch that rebinds the
trusted provider origin, repository, tag and commit, workflow/event/ref,
logical job, and exact run/job authority. The intended recovery contract is:

- a draft always starts with the archive/checksum pair and may then contain the
  service-proxy candidate, the candidate plus catalog, or the candidate plus
  catalog and manifest, but no other partial order or unexpected asset; recovery
  byte-verifies the deterministic candidate, authenticates an existing catalog
  attestation before accepting its image digests, validates the manifest against
  those exact payloads, and requires all five downloaded assets plus a valid
  checksum before publication;
- an already published crate is skipped only when its crates.io checksum
  exactly matches the local package archive;
- a checksum mismatch fails rather than assuming the version is equivalent;
  and
- once the attested draft catalog binds image digests, recovery does not rebuild
  them; missing version tags are created from those exact digests and any
  different or unbound version tag fails closed.

The handoff and the second credential-free `cargo package` output must match
byte for byte before publication is authorized. The credentialed executor does
not invoke Cargo: it frames and uploads those exact archive bytes using the
[official registry publish API](https://doc.rust-lang.org/cargo/reference/registry-web-api.html#publish)
over a fixed crates.io HTTPS connection with no proxy or redirect following.
It enforces crates.io's 10 MiB default archive limit and waits for the exact
public checksum after every upload before attempting a dependent crate. After
the normal 30-version burst for existing crates, it paces later uploads at one
per minute and stops before its conservative credential deadline. Future
authenticated recovery may skip only exact published checksums; any mismatch
must fail.

If a future publication stops after some crates reach crates.io, keep the tag
fixed and do not start a newer stable release. Recovery must wait for the
authenticated Automata dispatch path. Never move or recreate a public release
tag to repair a failed release. If the tagged source is wrong, publish a new
patch version. A crates.io version cannot be overwritten, and the future
workflow must treat a public GitHub Release as immutable.

The three GHCR `latest` updates are sequential and cannot be transactional. A
failure between them can temporarily leave one or two aliases ahead;
authenticated recovery must reapply and verify all three exact digests. Use
immutable version tags, not `latest`, as the release-completeness signal.

Finalization reconciles an error from `gh release edit` by re-reading the exact
public tag, prerelease/latest state, asset set and bytes, and annotated tag
identity. A runner termination after GitHub commits that edit but before the
reconciliation can still leave the workflow run marked failed; because the
release is then public and immutable, an authenticated recovery operation must
verify the terminal state without moving the tag. Automata dispatch must also
serialize recovery with new releases so a different draft cannot overtake it.

## Local distribution rehearsal

The development scripts can exercise the archive path without publishing:

```console
export AUTOMATA_EXPECTED_VERSION="$(./scripts/ci/workspace-version.sh)"
export AUTOMATA_EXPECTED_GIT_SHA="$(git rev-parse --verify 'HEAD^{commit}')"
export AUTOMATA_BUILD_GIT_SHA="$AUTOMATA_EXPECTED_GIT_SHA"
export AUTOMATA_RELEASE_CREATED="$(git show -s --format=%cI HEAD)"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"

./scripts/ci/build-static-musl.sh
./scripts/ci/verify-static-musl.sh
./scripts/ci/verify-sandbox-guest-static.sh
./scripts/ci/verify-service-proxy-static.sh
./scripts/ci/generate-sboms.sh
./scripts/ci/prepare-third-party-license-sources.sh
./scripts/ci/generate-third-party-licenses.sh
./scripts/ci/prepare-sandbox-guest-context.sh \
  target/sandbox-guest-context \
  "$AUTOMATA_EXPECTED_VERSION"
./scripts/ci/verify-sandbox-guest-image.sh \
  target/sandbox-guest-context \
  "$AUTOMATA_EXPECTED_VERSION" \
  "$AUTOMATA_EXPECTED_GIT_SHA" \
  "$AUTOMATA_RELEASE_CREATED" \
  "$SOURCE_DATE_EPOCH"
./scripts/ci/package-static-musl.sh
bash scripts/ci/tests/install.test.sh
bash scripts/ci/tests/container-context.test.sh
```

The exact tool prerequisites are listed in the
[development guide](development.md). These scripts write only under `target/`;
none of the commands above publishes a crate, image, or release.
