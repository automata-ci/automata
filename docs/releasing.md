# Releasing Automata

The release workflow turns one reviewed version tag into a crates.io workspace,
two GHCR images, and a GitHub Release containing the verified static Linux
archive. This is an operator guide; normal users should follow
[getting started](getting-started.md).

> [!IMPORTANT]
> No public Automata release has been published yet. The first run needs the
> one-time repository and registry setup below. Publishing is intentionally
> non-atomic: crates.io versions become permanent before the GitHub Release is
> made public, so failures must be retried from the same immutable tag.

## What a release publishes

For workspace version `X.Y.Z`, tag `vX.Y.Z` publishes:

| Destination | Published names |
| --- | --- |
| crates.io | Every publishable workspace package in dependency order, including `automata-ci` and `automata-ci-runner` |
| GitHub Release | `automata-x86_64-unknown-linux-musl.tar.gz`, its `.sha256` file, and `automata-release-manifest.json` |
| GHCR | `ghcr.io/automata-ci/automata:X.Y.Z` and `ghcr.io/automata-ci/automata-runner:X.Y.Z` |
| Stable aliases | Both GHCR images also receive `latest` for a non-prerelease version |
| Attestations | The release archive, checksum, and both image digests |

The archive contains `automata`, `automata-runner`, the license, third-party
notices, SBOMs, a version file, and internal checksums. The filename stays
stable across versions so the installer can use GitHub's `latest/download` URL;
the release tag supplies the version boundary.

## One-time repository setup

### 1. Create the protected publication environments

In **Settings → Environments**, create environments named `release`,
`crates-io`, and `profile-promotion`. Do not dispatch either publication
workflow until all three exist with the rules below. Allow `release` and
`crates-io` deployments from the protected default branch and tags matching
`v*` convention used by the repository; tag pushes use `v*`, while manual
same-tag retries are dispatched from the default branch. Keep `release` as the
unattended staging boundary without required reviewers. On `crates-io`, add at
least one required reviewer and prevent self-review because it authorizes
irreversible package publication.

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

After the first release succeeds, configure a trusted GitHub publisher for
every Automata crate, restricted to this repository, `release.yml`, and the
`crates-io` environment. Set the `crates-io` environment variable
`CRATES_IO_TRUSTED_PUBLISHING=true`, delete the bootstrap secret, and revoke the
token on crates.io. Future runs then use crates.io's short-lived OIDC token,
which the workflow revokes automatically. The crates.io team documents both the
[first-release requirement](https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07/)
and the [official authentication action](https://github.com/rust-lang/crates-io-auth-action).

Before creating the first tag, set the repository variable
`CRATES_IO_EXPECTED_OWNER_LOGINS` to the sorted, comma-separated crates.io
logins that must exactly own any already-claimed Automata name. Crate names are
[first come, first served](https://doc.rust-lang.org/cargo/reference/publishing.html#before-publishing-a-new-crate),
so the gate checks every workspace name before any staging mutation and repeats
the owner audit immediately before the first upload.

The workspace currently needs far more new names than crates.io's normal burst
of five; the standard limit then permits only one new crate every ten minutes.
Obtain a temporary initial-publish override for the exact bootstrap account from
crates.io support before tagging, following the
[official rate-limit guidance](https://crates.io/docs/rate-limits). Only after
written confirmation, set the repository variable
`CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED=true`. Remove it after the initial
names are claimed. Without that explicit confirmation the workflow fails in the
read-only gate, before drafts, images, attestations, or packages are created.
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

The workflow publishes GHCR with its short-lived `GITHUB_TOKEN`; it does not
need a stored registry password.

GitHub's `id-token` permission is job-wide rather than step-scoped. The
`crates-io` job therefore checks out no repository and runs no build or
dependency command. Before the explicit crates.io authentication action, it
runs only pinned artifact-download code, fixed runner clients, bounded
materialization, and the three small release helpers from a same-run raw tool
bundle selected by artifact ID and verified against both the artifact-service
digest and the preparation-job SHA-256. Those helpers are part of the audited
credential-bound trusted code; changes to them require the same review as the
workflow itself.

### 4. Enable private security reporting and dependency alerts

Before making the repository public, enable **Private vulnerability reporting**
under **Settings → Security → Code security and analysis**. Confirm that the
private report link in [SECURITY.md](../SECURITY.md) opens for a logged-in test
account. Enable the dependency graph, Dependabot alerts, and Dependabot security
updates in the same settings area. The checked-in `.github/dependabot.yml`
enables scheduled version-update pull requests; repository settings still
control alerts and security updates.

### 5. Enable GitHub Pages from Actions

Under **Settings → Pages → Build and deployment**, select **GitHub Actions**
as the source. The least-privilege `pages.yml` workflow builds the static UI demo
and screenshots from `main`; its deploy job alone receives `pages: write` and
`id-token: write`, and manual dispatches from other branches are skipped. Restrict
the `github-pages` environment to the default branch as defense in depth. Pull
request review runs use per-PR concurrency groups, separate from the serialized
main deployment group. Run the workflow once manually from `main` or merge a
reviewed `ui/` change, then confirm <https://automata-ci.github.io/automata/> is
public before publishing crates whose homepage metadata points there.

### 6. Plan the first GHCR visibility change

New organization container packages are private by default. After the first
workflow pushes `automata` and `automata-runner`, an organization owner or
package administrator must change both packages to **Public** under their
package settings. Public Container Registry packages can then be pulled
anonymously; GitHub documents the irreversible visibility change in
[Configuring package access and visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

The workflow tests anonymous manifest access before publishing any permanent
crate version. On the first run it may stop at that check by design. Make both
images public, then rerun the same tag with the manual workflow input. Do not
create a new version merely to complete this one-time step.

### 7. Protect the release identity

Use a repository ruleset to restrict creation, update, and deletion of `v*` tags
to release maintainers. Enable GitHub's
[immutable releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases)
before the first public tag. The workflow already refuses moved tags and
published releases; the repository settings enforce the same boundary outside
the workflow.

## Publish the runner profile

The Ubuntu runner profile is released independently through
`.github/workflows/profile-image.yml`. Its two manual operations form a review
boundary:

1. Dispatch `build-candidate` from the default branch and supply the full source
   commit SHA containing the proposed Containerfile and profile contract.
2. Review the reported exact registry digest and its provenance, SPDX SBOM,
   source identity, and runtime checks.
3. Update `images/github-hosted-ubuntu-24.04-x64/profile-manifest.json`, its
   hashes in the adjacent `profile-lock.json`, and
   `crates/automata-ci-runner/config/runner.local.example.json` to that digest;
   merge the reviewed lock change. v0.1 has no composed control-plane profile
   catalog file, so image promotion alone does not enable hosted-label
   scheduling; add and review that product configuration before activation.
4. Make `ghcr.io/automata-ci/automata-ubuntu-24.04-x64` public.
5. Dispatch `promote-locked` from the default branch, paste the locked digest,
   and approve the protected `profile-promotion` environment.

Promotion copies the already-reviewed digest to `profile-v1` and `latest`; it
does not rebuild from mutable package repositories. After environment approval,
promotion scrubs checkout credentials and rechecks that the remote default
branch still equals the reviewed dispatch SHA immediately before copying the
digest; if `main` moved, dispatch the promotion again. Candidate builds and
promotions use independent concurrency groups, so a later candidate dispatch
cannot replace a pending promotion. The detailed contract and local build path
live in the
[profile guide](../images/github-hosted-ubuntu-24.04-x64/README.md).

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

Create one annotated tag whose name exactly matches the workspace version. The
workflow retains and revalidates both the tag object and its peeled commit, so a
lightweight replacement or a newly annotated object at the same commit fails:

```console
version="$(./scripts/ci/workspace-version.sh)"
git status --short
git tag --annotate "v${version}" --message "Automata ${version}"
git push origin "v${version}"
```

Only tag a reviewed release commit. The workflow rejects a tag that does not
equal `v` plus the workspace version, a mismatched checkout, or a dirty release
build.

The tag push starts `.github/workflows/release.yml`. Every version shares one
repository-wide publication lock, so crates.io publication and the two global
`latest` aliases cannot race another release. A different unfinished draft
blocks the next tag, and a stable version must be newer than every stable GitHub
Release already published. It performs these gates in order:

1. prove that the tag commit is on `main` and that CI passed for that exact SHA;
2. stage every crate and exercise both static musl executables inside the
   protected `release` environment;
3. generate SBOMs, license material, the deterministic archive, checksums, and
   the canonical release manifest;
4. create or recover the exact draft, verify its accepted bytes, attest the
   archive, and bind the two image digests before creating version tags;
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
9. move both GHCR `latest` aliases only for a stable release and verify them; and
10. revalidate the remote tag, release order, version images, and draft bytes in
    the last pre-publication window, then make the GitHub Release public without
    OIDC credentials.

Versions containing a prerelease suffix publish as GitHub prereleases and do
not move either GHCR `latest` tag.

## Verify the published release

For a non-prerelease, verify every public installation surface without registry
credentials:

```console
version="$(./scripts/ci/workspace-version.sh)"

curl --fail --location \
  "https://github.com/automata-ci/automata/releases/download/v${version}/automata-x86_64-unknown-linux-musl.tar.gz.sha256"
cargo search automata-ci --limit 1
podman manifest inspect "ghcr.io/automata-ci/automata:${version}" >/dev/null
podman manifest inspect "ghcr.io/automata-ci/automata-runner:${version}" >/dev/null
```

Test the installer on a disposable x86-64 Linux account or container, confirm
both `--version` outputs, start `automata preview`, and check `/healthz` and
`/readyz`. Do not test a release by overwriting a production installation
before the disposable verification passes.

## Retry and failure behavior

Use **Actions → Release → Run workflow** from the default branch with the
existing tag when a transient step fails. The workflow is designed for same-tag
retries:

- an interrupted draft may contain the archive/checksum pair, the canonical
  manifest, all three, or none, but no unexpected asset; the workflow
  byte-verifies every existing asset, uploads only an absent expected member,
  and requires the exact three downloaded bytes plus a valid checksum before
  publication;
- an already published crate is skipped only when its crates.io checksum
  exactly matches the local package archive;
- a checksum mismatch fails rather than assuming the version is equivalent;
  and
- once the draft manifest binds image digests, retries do not rebuild them;
  missing version tags are created from those exact digests and any different or
  unbound version tag fails closed.

The handoff and the second credential-free `cargo package` output must match
byte for byte before publication is authorized. The credentialed executor does
not invoke Cargo: it frames and uploads those exact archive bytes using the
[official registry publish API](https://doc.rust-lang.org/cargo/reference/registry-web-api.html#publish)
over a fixed crates.io HTTPS connection with no proxy or redirect following.
It enforces crates.io's 10 MiB default archive limit and waits for the exact
public checksum after every upload before attempting a dependent crate. After
the normal 30-version burst for existing crates, it paces later uploads at one
per minute and stops before its conservative credential deadline. A timeout or
rate-limit response is recovered by rerunning the same tag; exact published
checksums are skipped and any mismatch fails.

If publication stops after some crates reach crates.io, keep the tag fixed and
rerun before starting a newer stable release. Never move or recreate a public
release tag to repair a failed release. If the tagged source is wrong, publish a
new patch version. A crates.io version cannot be overwritten, and the workflow
treats a public GitHub Release as immutable.

The two GHCR `latest` updates are sequential and cannot be transactional. A
failure between them can temporarily leave one alias ahead; the same-tag retry
reapplies and verifies both exact digests. Use immutable version tags, not
`latest`, as the release-completeness signal.

Finalization reconciles an error from `gh release edit` by re-reading the exact
public tag, prerelease/latest state, asset set and bytes, and annotated tag
identity. A runner termination after GitHub commits that edit but before the
reconciliation can still leave the workflow run marked failed; because the
release is then public and immutable, verify the terminal state rather than
rerunning or moving the tag.

GitHub retains only one pending run for a concurrency group with the checked-in
workflow syntax, so do not queue several release dispatches at once: wait for
the current run to finish or fail before dispatching its retry. A different
draft must be completed before the workflow accepts a new tag.

## Local distribution rehearsal

The development scripts can exercise the archive path without publishing:

```console
export AUTOMATA_EXPECTED_VERSION="$(./scripts/ci/workspace-version.sh)"
export AUTOMATA_EXPECTED_GIT_SHA="$(git rev-parse --verify 'HEAD^{commit}')"
export AUTOMATA_BUILD_GIT_SHA="$AUTOMATA_EXPECTED_GIT_SHA"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"

./scripts/ci/build-static-musl.sh
./scripts/ci/verify-static-musl.sh
./scripts/ci/generate-sboms.sh
./scripts/ci/prepare-third-party-license-sources.sh
./scripts/ci/generate-third-party-licenses.sh
./scripts/ci/package-static-musl.sh
bash scripts/ci/tests/install.test.sh
bash scripts/ci/tests/container-context.test.sh
```

The exact tool prerequisites are listed in the
[development guide](development.md). These scripts write only under `target/`;
none of the commands above publishes a crate, image, or release.
