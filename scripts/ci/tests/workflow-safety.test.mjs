import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(testDirectory, "../../..");

function source(relativePath) {
  return readFileSync(path.join(repositoryRoot, relativePath), "utf8");
}

function filesRecursively(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...filesRecursively(entryPath));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
  return files;
}

function ignoredRustSuites() {
  const cratesRoot = path.join(repositoryRoot, "crates");
  const suites = [];
  for (const file of filesRecursively(cratesRoot)) {
    if (!file.endsWith(".rs")) continue;
    const relativePath = path.relative(repositoryRoot, file).split(path.sep).join("/");
    for (const match of readFileSync(file, "utf8").matchAll(
      /#\[ignore(?:\s*=\s*"([^"]+)")?\]/g,
    )) {
      suites.push({ reason: match[1] ?? "", relativePath });
    }
  }
  return suites;
}

function requiresOnlyTestDatabase(reason) {
  return (
    reason.includes("AUTOMATA_TEST_DATABASE_URL") &&
    !/(?:AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE|Podman|public GitHub (?:access|network)|RustFS|S3-compatible)/i.test(
      reason,
    )
  );
}

function section(text, start, end) {
  const startIndex = text.indexOf(start);
  assert.notEqual(startIndex, -1, `missing section start: ${start}`);
  const endIndex = text.indexOf(end, startIndex + start.length);
  assert.notEqual(endIndex, -1, `missing section end: ${end}`);
  return text.slice(startIndex, endIndex);
}

function checkReleaseOrder(
  pages,
  { tag = "v1.2.3", version = "1.2.3", prerelease = false } = {},
) {
  return spawnSync(
    "python3",
    [
      path.join(repositoryRoot, "scripts/ci/check-release-order.py"),
      "--requested-tag",
      tag,
      "--version",
      version,
      "--prerelease",
      String(prerelease),
    ],
    {
      encoding: "utf8",
      input: JSON.stringify(pages),
    },
  );
}

function releaseJobs() {
  const release = source(".github/workflows/release.yml");
  return {
    crates: section(release, "\n  publish_crates:", "\n  finalize_release:"),
    finalize: release.slice(release.indexOf("\n  finalize_release:")),
    gate: section(release, "\n  gate:", "\n  stage_release:"),
    prepare: section(release, "\n  prepare_crates:", "\n  publish_crates:"),
    release,
    stage: section(release, "\n  stage_release:", "\n  prepare_crates:"),
  };
}

test("CI pins PostgreSQL 18 and covers every database-only ignored suite", () => {
  const ci = source(".github/workflows/ci.yml");
  const verify = section(ci, "\n  verify:", "\n  frontend:");
  const databaseCheck = section(
    verify,
    "      - name: Verify isolated PostgreSQL 18 test database",
    "      - name: Test PostgreSQL invariants",
  );
  const databaseTests = section(
    verify,
    "      - name: Test PostgreSQL invariants",
    "      - name: Install cargo-deny",
  );

  assert.match(
    verify,
    /image: docker\.io\/library\/postgres:18\.4-bookworm@sha256:7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568/,
  );
  assert.match(verify, /postgresql-client/);
  assert.doesNotMatch(verify, /sudo service postgresql|CREATE ROLE|CREATE DATABASE/);
  assert.match(databaseCheck, /server_version/);
  assert.match(databaseCheck, /"180004"/);
  assert.match(databaseTests, /AUTOMATA_TEST_DATABASE_URL/);
  assert.doesNotMatch(
    databaseTests,
    /--workspace|--all-targets|automata-ci-results-github --tests/,
  );
  assert.equal((databaseTests.match(/^\s+cargo test /gm) ?? []).length, 7);

  const broadDatabasePackages = new Set([
    "automata-ci-auth-postgres",
    "automata-ci-runner-auth-postgres",
    "automata-ci-secret-postgres",
    "automata-ci-store",
  ]);
  for (const packageName of broadDatabasePackages) {
    const command =
      `cargo test -p ${packageName} --tests --all-features --locked ` +
      "-- --ignored --test-threads=1";
    assert.equal(
      databaseTests.split(command).length - 1,
      1,
      `${packageName} database suite must run exactly once`,
    );
  }
  const explicitDatabaseTargets = new Map([
    ["automata-ci", new Set(["github_provider_end_to_end_matrix"])],
    ["automata-ci-results-github", new Set(["postgres_artifacts", "postgres_cache"])],
  ]);
  for (const [packageName, targets] of explicitDatabaseTargets) {
    for (const target of targets) {
      const command =
        `cargo test -p ${packageName} --test ${target} ` +
        "--all-features --locked -- --ignored --test-threads=1";
      assert.equal(
        databaseTests.split(command).length - 1,
        1,
        `the database-only ${packageName}/${target} suite must run exactly once`,
      );
    }
  }

  const ignored = ignoredRustSuites();
  const broadExternalSuites = ignored.filter(({ reason, relativePath }) => {
    const packageName = relativePath.split("/")[1];
    return broadDatabasePackages.has(packageName) && !requiresOnlyTestDatabase(reason);
  });
  assert.deepEqual(
    broadExternalSuites,
    [],
    "a broad database package gained an ignored suite with another prerequisite",
  );

  const databaseOnlySuites = new Set();
  for (const { reason, relativePath } of ignored) {
    if (!requiresOnlyTestDatabase(reason)) continue;
    const parts = relativePath.split("/");
    assert.equal(parts[0], "crates");
    assert.equal(parts[2], "tests", `${relativePath} is not an integration-test target`);
    assert.equal(parts.length, 4, `${relativePath} needs an explicit CI target mapping`);
    const packageName = parts[1];
    const testTarget = path.basename(parts[3], ".rs");
    const suite = `${packageName}/${testTarget}`;
    databaseOnlySuites.add(suite);
    assert.ok(
      broadDatabasePackages.has(packageName) ||
        explicitDatabaseTargets.get(packageName)?.has(testTarget),
      `${suite} requires only the test database but is not covered by CI`,
    );
  }
  assert.ok(databaseOnlySuites.size > broadDatabasePackages.size);
});

test("CI executes documentation and committed script contract suites", () => {
  const ci = source(".github/workflows/ci.yml");
  const verify = section(ci, "\n  verify:", "\n  frontend:");
  const rustTests = section(
    verify,
    "      - name: Test\n",
    "      - name: Check public API documentation",
  );
  const shellContracts = section(
    verify,
    "      - name: Lint workflows and shell scripts",
    "      - name: Verify Prometheus metrics contract",
  );
  const dependencyContracts = section(
    verify,
    "      - name: Install cargo-deny",
    "      - name: Audit dependencies",
  );

  assert.match(
    rustTests,
    /cargo test --workspace --all-targets --all-features --locked/,
  );
  assert.match(
    rustTests,
    /cargo test --workspace --doc --all-features --locked/,
  );
  assert.match(shellContracts, /renderer-preflight\.test\.sh/);
  assert.match(shellContracts, /renderer-provenance\.test\.sh/);
  assert.match(shellContracts, /regenerate-renderer-atomicity\.test\.sh/);
  assert.match(shellContracts, /deploy\/observability\/inventory\/\*\.sh/);
  assert.match(shellContracts, /inventory-scratch\.test\.sh/);
  assert.match(shellContracts, /release-handoff\.test\.py/);
  assert.match(
    dependencyContracts,
    /scripts\/ui\/tests\/rquickjs-macro-diagnostics\.test\.sh/,
  );
  assert.match(ci, /node --test scripts\/ci\/tests\/\*\.test\.mjs/);
  assert.match(
    source("scripts/ci/verify-product-targets.sh"),
    /scripts\/ci\/tests\/publish-crates\.test\.py/,
  );
  assert.match(
    source("scripts/ci/verify-product-targets.sh"),
    /publish-crates\.py" --list-publishable/,
  );
});

test("pull requests retain the distribution gate when renderer reproduction is skipped", () => {
  const ci = source(".github/workflows/ci.yml");
  const renderer = section(ci, "\n  renderer:", "\n  dist:");
  const dist = ci.slice(ci.indexOf("\n  dist:"));

  assert.match(renderer, /if: \$\{\{ github\.event_name != 'pull_request' \}\}/);
  assert.match(dist, /needs:\n      - verify\n      - frontend\n      - renderer/);
  assert.match(
    dist,
    /if: \$\{\{ !cancelled\(\) && needs\.verify\.result == 'success' && needs\.frontend\.result == 'success' && \(needs\.renderer\.result == 'success' \|\| \(github\.event_name == 'pull_request' && needs\.renderer\.result == 'skipped'\)\) \}\}/,
  );
});

test("Pages and profile publication isolate concurrency and environments", () => {
  const pages = source(".github/workflows/pages.yml");
  const profile = source(".github/workflows/profile-image.yml");
  const promote = profile.slice(profile.indexOf("\n  promote:"));

  assert.match(
    pages,
    /group: pages-\$\{\{ github\.event_name == 'pull_request' && format\('pr-\{0\}', github\.event\.pull_request\.number\) \|\| github\.ref \}\}/,
  );
  assert.match(
    pages,
    /cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}/,
  );
  assert.match(
    profile,
    /group: publish-runner-profile-\$\{\{ inputs\.operation \}\}/,
  );
  assert.match(promote, /environment: profile-promotion/);
});

test("release publication is globally serialized and fails early on registry capacity", () => {
  const { gate, release } = releaseJobs();
  const identity = section(
    gate,
    "      - name: Validate release identity",
    "      - name: Require unambiguous release order",
  );
  const stableOrder = section(
    gate,
    "      - name: Require unambiguous release order",
    "      - name: Require crates.io name ownership and first-publish capacity",
  );
  const capacity = section(
    gate,
    "      - name: Require crates.io name ownership and first-publish capacity",
    "      - name: Require successful main CI for the tagged commit",
  );

  assert.match(
    release,
    /concurrency:\n  group: automata-public-release\n  cancel-in-progress: false/,
  );
  assert.match(identity, /manual release retries must run from %s/);
  assert.match(identity, /refs\/heads\/\$\{DEFAULT_BRANCH\}/);
  assert.match(identity, /git cat-file -t "\$tag_object"/);
  assert.match(stableOrder, /gh api --paginate --slurp/);
  assert.match(stableOrder, /scripts\/ci\/check-release-order\.py/);
  assert.match(capacity, /publish-crates\.py --check-capacity/);
  assert.match(capacity, /CRATES_IO_EXPECTED_OWNER_LOGINS/);
  assert.match(capacity, /CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED/);
  assert.match(capacity, /owner_logins=%s/);
  assert.match(capacity, /initial_burst_override_approved=%s/);
  assert.match(release, /Revalidate identity before the first staging mutation/);
  assert.match(release, /Revalidate identity before the immutable image binding/);
});

test("release order validation handles drafts, retries, and stable monotonicity", () => {
  assert.equal(checkReleaseOrder([[]]).status, 0);
  assert.equal(
    checkReleaseOrder([[{ tag_name: "v1.2.3", draft: true, prerelease: false }]])
      .status,
    0,
  );

  const unfinished = checkReleaseOrder([
    [{ tag_name: "v1.2.2", draft: true, prerelease: false }],
  ]);
  assert.notEqual(unfinished.status, 0);
  assert.match(unfinished.stderr, /unfinished release draft must be resolved first/);

  const alreadyPublic = checkReleaseOrder([
    [{ tag_name: "v1.2.3", draft: false, prerelease: false }],
  ]);
  assert.notEqual(alreadyPublic.status, 0);
  assert.match(alreadyPublic.stderr, /already public and immutable/);

  assert.equal(
    checkReleaseOrder([
      [{ tag_name: "v1.2.2", draft: false, prerelease: false }],
    ]).status,
    0,
  );
  const rollback = checkReleaseOrder([
    [{ tag_name: "v2.0.0", draft: false, prerelease: false }],
  ]);
  assert.notEqual(rollback.status, 0);
  assert.match(rollback.stderr, /after newer stable release v2\.0\.0/);

  assert.equal(
    checkReleaseOrder(
      [[{ tag_name: "v2.0.0", draft: false, prerelease: false }]],
      { tag: "v1.2.3-rc.1", version: "1.2.3-rc.1", prerelease: true },
    ).status,
    0,
  );
});

test("release jobs isolate build, crates OIDC, and credential-free finalization", () => {
  const { crates, finalize, prepare, release, stage } = releaseJobs();

  assert.match(stage, /needs: gate/);
  assert.match(stage, /environment: release/);
  assert.match(stage, /id-token: write/);
  assert.match(stage, /packages: write/);

  assert.match(prepare, /needs: \[gate, stage_release\]/);
  assert.match(prepare, /permissions:\n      contents: read/);
  assert.doesNotMatch(prepare, /id-token: write|environment:/);
  assert.match(prepare, /publish-crates\.py --list-publishable/);
  assert.match(
    prepare,
    /cargo package --locked --no-verify "\$\{package_arguments\[@\]\}"/,
  );
  assert.match(prepare, /--prepare target\/release-publish-plan\.json/);
  assert.match(stage, /publish-crates\.py --list-publishable/);
  assert.match(stage, /common\+=\(--expected-crate "\$crate"\)/);
  assert.doesNotMatch(release, /cargo package --workspace/);

  assert.match(crates, /needs: \[gate, stage_release, prepare_crates\]/);
  assert.match(crates, /environment: crates-io/);
  assert.match(
    release,
    /publish_crates:[\s\S]+?permissions:\n      contents: read\n      id-token: write\n/,
  );
  assert.doesNotMatch(crates, /packages: write|attestations: write|contents: write/);
  assert.doesNotMatch(
    crates,
    /cargo (?:build|metadata|package|publish)|npm |pnpm |yarn |--prepare(?:\s|$)/,
  );
  assert.doesNotMatch(crates, /actions\/checkout@/);
  assert.match(crates, /Download same-run raw publisher tools by artifact ID/);
  assert.match(crates, /needs\.prepare_crates\.outputs\.tools_artifact_id/);
  assert.match(crates, /publisher tool archive digest changed/);
  assert.match(crates, /PUBLISH_ROOT/);
  assert.match(crates, /--execute-prepared "\$PUBLICATION_PLAN"/);

  assert.match(
    finalize,
    /needs: \[gate, stage_release, prepare_crates, publish_crates\]/,
  );
  assert.match(finalize, /permissions:\n      contents: write\n      packages: write/);
  assert.doesNotMatch(finalize, /id-token: write|environment:/);

  const credentialBoundary = crates.slice(
    crates.indexOf("      - name: Request short-lived crates.io credentials"),
  );
  assert.match(
    credentialBoundary,
    /- name: Publish exact prepared crates\.io archives/,
  );
  assert.equal((credentialBoundary.match(/      - name:/g) ?? []).length, 2);
  assert.ok(
    crates.indexOf("Revalidate release state after crates.io environment approval") <
      crates.indexOf("Request short-lived crates.io credentials"),
  );
  assert.match(
    credentialBoundary,
    /needs\.gate\.outputs\.crates_io_owner_logins/,
  );
  assert.match(
    credentialBoundary,
    /needs\.gate\.outputs\.crates_io_initial_burst_override_approved/,
  );
});

test("same-run raw payloads are selected by ID and verified by two digests", () => {
  const { crates, finalize, prepare, stage } = releaseJobs();

  assert.match(stage, /actions\/upload-artifact@[0-9a-f]{40}/);
  assert.match(stage, /archive: false/);
  assert.match(stage, /retention-days: 90/);
  assert.match(stage, /artifact_digest="\$\{ARTIFACT_DIGEST#sha256:\}"/);
  assert.match(stage, /artifact_digest" == "\$HANDOFF_SHA256/);
  for (const consumer of [prepare, crates, finalize]) {
    assert.match(consumer, /actions\/download-artifact@[0-9a-f]{40}/);
    assert.match(
      consumer,
      /artifact-ids: \$\{\{ needs\.stage_release\.outputs\.handoff_artifact_id \}\}/,
    );
    assert.match(consumer, /skip-decompress: true/);
    assert.match(consumer, /digest-mismatch: error/);
    assert.doesNotMatch(consumer, /github-token:|run-id:|repository:/);
    assert.match(consumer, /release-handoff\.py"? verify-handoff/);
    assert.match(consumer, /manifest_sha256=\$\{MANIFEST_SHA256\}/);
    assert.match(consumer, /find [^\n]+ -mindepth 1 -maxdepth 1/);
    assert.match(consumer, /-print0/);
    assert.match(consumer, /-f "\$(?:handoff|expected)"/);
    assert.match(consumer, /! -L "\$(?:handoff|expected)"/);
  }

  assert.match(prepare, /Upload raw immutable publication plan/);
  assert.match(prepare, /archive: false/);
  assert.match(prepare, /artifact service digest differs from the publication plan/);
  assert.match(
    crates,
    /artifact-ids: \$\{\{ needs\.prepare_crates\.outputs\.plan_artifact_id \}\}/,
  );
  assert.match(crates, /PLAN_ARTIFACT_DIGEST#sha256:/);
});

test("consumers revalidate tag, draft bytes, order, and bound images", () => {
  const { crates, finalize, prepare } = releaseJobs();

  for (const consumer of [prepare, crates, finalize]) {
    const revalidation = consumer.indexOf("git ls-remote --exit-code");
    assert.notEqual(revalidation, -1);
    assert.match(
      consumer.slice(0, revalidation),
      /env -u CARGO_REGISTRY_TOKEN -u GH_TOKEN -u GITHUB_TOKEN/,
    );
    assert.match(consumer, /refs\/tags\/\$\{RELEASE_TAG\}\^\{\}/);
    assert.match(consumer, /automata-release-manifest\.json/);
    assert.match(consumer, /cmp -- "\$archive"/);
    assert.match(consumer, /cmp -- "\$checksum"/);
    assert.match(consumer, /cmp -- "\$manifest"/);
    assert.match(consumer, /check-release-order\.py/);
    assert.match(consumer, /docker buildx imagetools inspect/);
  }

  assert.ok(
    crates.indexOf("Revalidate release state after crates.io environment approval") <
      crates.indexOf("Request short-lived crates.io credentials"),
  );
  assert.match(crates, /GH_REPO: \$\{\{ github\.repository \}\}/);
});

test("image retries are bound before immutable version tags are created", () => {
  const { stage } = releaseJobs();

  assert.match(stage, /Recover immutable image binding from the draft/);
  assert.match(stage, /Refuse unbound version image tags/);
  assert.match(stage, /push-by-digest=true/);
  assert.doesNotMatch(stage, /tags: ghcr\.io\/automata-ci\/automata:/);
  assert.ok(
    stage.indexOf("Bind new image digests in the draft manifest") <
      stage.indexOf("Create or verify immutable version image tags"),
  );
  assert.match(stage, /immutable version tag mismatch/);
  assert.doesNotMatch(stage, /gh release upload[^\n]+--clobber/);
});

test("final publication reconciles the exact immutable GitHub state", () => {
  const { finalize, stage } = releaseJobs();

  assert.match(stage, /prerelease_args=\(\)/);
  assert.match(stage, /true\) prerelease_args=\(--prerelease\)/);
  assert.match(stage, /gh release create[\s\S]+"\$\{prerelease_args\[@\]\}"/);
  assert.doesNotMatch(stage, /--json isDraft,assets/);
  assert.match(finalize, /require_exact_published_release\(\)/);
  assert.match(finalize, /--json isDraft,isPrerelease,assets/);
  assert.match(finalize, /draft release prerelease state differs/);
  assert.match(finalize, /--json isDraft,isPrerelease,tagName,assets/);
  assert.match(finalize, /repos\/\$\{GITHUB_REPOSITORY\}\/releases\/latest/);
  assert.match(finalize, /edit_status=0/);
  assert.ok(
    finalize.indexOf("Reconcile exact crates.io versions before alias promotion") <
      finalize.indexOf("Sign in to GHCR for stable alias promotion"),
  );
  assert.match(finalize, /--verify-published/);
  assert.match(finalize, /--draft=false --prerelease=false --latest/);
  const edit = finalize.lastIndexOf("gh release edit");
  const releaseOrder = finalize.lastIndexOf("require_release_order\n");
  const versionImages = finalize.lastIndexOf(
    'ghcr.io/automata-ci/automata-runner "$RUNNER_DIGEST"',
  );
  const reconciliation = finalize.lastIndexOf("require_exact_published_release\n");
  assert.notEqual(edit, -1);
  assert.notEqual(releaseOrder, -1);
  assert.notEqual(versionImages, -1);
  assert.ok(releaseOrder < edit);
  assert.ok(versionImages < edit);
  assert.ok(edit < reconciliation);
  assert.match(
    finalize.slice(reconciliation),
    /^require_exact_published_release\n\s+verify_remote_release_assets\n\s+require_remote_release_commit/m,
  );
  assert.doesNotMatch(finalize, /if\s+!\s+require_exact_published_release/);

  const failClosed = spawnSync(
    "bash",
    [
      "--noprofile",
      "--norc",
      "-e",
      "-o",
      "pipefail",
      "-c",
      `postcondition() {
        false | true
        printf 'masked\\n'
      }
      postcondition
      printf 'continued\\n'`,
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(failClosed.status, 0);
  assert.equal(failClosed.stdout, "");
});

test("profile promotion rechecks the reviewed default-branch head", () => {
  const profile = source(".github/workflows/profile-image.yml");
  const freshness = section(
    profile,
    "      - name: Scrub checkout credentials and require current default-branch head",
    "      - name: Promote exact digest without rebuilding",
  );
  assert.match(freshness, /env[\s\S]+-u GH_TOKEN[\s\S]+-u GITHUB_TOKEN/);
  assert.match(freshness, /ls-remote --exit-code --refs/);
  assert.match(freshness, /GITHUB_SHA/);
  assert.match(freshness, /remote_sha != dispatch_sha/);
});

test("release documentation requires all publication controls", () => {
  const guide = source("docs/releasing.md");
  const release = source(".github/workflows/release.yml");
  const productPolicy = source("scripts/ci/verify-product-targets.sh");
  assert.match(guide, /`release`,\n`crates-io`, and `profile-promotion`/);
  assert.match(guide, /`release` as the\nunattended staging boundary/);
  assert.match(
    guide,
    /`crates-io`[\s\S]+required reviewer[\s\S]+prevent self-review/,
  );
  assert.match(
    guide,
    /`profile-promotion`[\s\S]+default branch only[\s\S]+required reviewer/,
  );
  assert.match(guide, /CRATES_IO_EXPECTED_OWNER_LOGINS/);
  assert.match(guide, /CRATES_IO_INITIAL_BURST_OVERRIDE_APPROVED=true/);
  assert.match(guide, /crates\.io\/docs\/rate-limits/);
  assert.match(guide, /rechecks?[^.]+default\s+branch/i);
  assert.match(guide, /ordinary CI permits a truthful pre-tag changelog/);
  assert.match(
    release,
    /\[Unreleased\]: https:\/\/github\.com\/automata-ci\/automata\/compare\/v\$\{version\}\.\.\.HEAD/,
  );
  assert.match(
    release,
    /\[\$\{version\}\]: https:\/\/github\.com\/automata-ci\/automata\/releases\/tag\/v\$\{version\}/,
  );
  assert.doesNotMatch(productPolicy, /lacks a dated .* release entry/);
});
