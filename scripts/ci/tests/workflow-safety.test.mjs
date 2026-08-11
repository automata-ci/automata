import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(testDirectory, "../../..");

function source(relativePath) {
  return readFileSync(path.join(repositoryRoot, relativePath), "utf8").replace(
    /\r\n/g,
    "\n",
  );
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

function workflowJob(text, name) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const start = new RegExp(`^  ${escapedName}:[ \\t]*\\r?$`, "m").exec(text);
  assert.ok(start, `missing workflow job: ${name}`);
  const contentStart = start.index + start[0].length;
  const nextJob = /^  [A-Za-z_][A-Za-z0-9_-]*:[ \t]*\r?$/m.exec(
    text.slice(contentStart),
  );
  const endIndex = nextJob ? contentStart + nextJob.index : text.length;
  return text.slice(start.index, endIndex);
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

function serviceProxyJobs() {
  const workflow = source(".github/workflows/service-proxy-image.yml");
  return {
    candidate: section(workflow, "\n  candidate:", "\n  promotion_verify:"),
    candidateBuild: section(
      workflow,
      "\n  candidate_build:",
      "\n  candidate:",
    ),
    promotionVerify: section(
      workflow,
      "\n  promotion_verify:",
      "\n  promote:",
    ),
    promote: workflow.slice(workflow.indexOf("\n  promote:")),
    validate: section(workflow, "\n  validate:", "\n  candidate_build:"),
    workflow,
  };
}

function assertRegistryAttestationsUsePrivateHome(
  job,
  { expectedCount, home },
) {
  assert.ok(
    job.includes(`ATTESTATION_HOME: \${{ github.workspace }}/${home}`),
  );
  assert.ok(
    job.includes(`DOCKER_CONFIG: \${{ github.workspace }}/${home}/.docker`),
  );
  const registryAttestations = job
    .split(/^      - name: /m)
    .filter(
      (step) =>
        step.includes("uses: actions/attest@") &&
        step.includes("push-to-registry: true"),
    );
  assert.equal(registryAttestations.length, expectedCount);
  for (const step of registryAttestations) {
    assert.match(
      step,
      /env:\n          HOME: \$\{\{ env\.ATTESTATION_HOME \}\}\n        uses: actions\/attest@/,
    );
  }
  assert.match(job, /rm -f --[\s\S]*"\$DOCKER_CONFIG\/config\.json"/);
}

test("CI pins PostgreSQL 18 and covers every database-only ignored suite", () => {
  const ci = source(".github/workflows/ci.yml");
  const store = workflowJob(ci, "postgres_store");
  const integrations = workflowJob(ci, "postgres_integrations");
  const storeShard = source("scripts/ci/run-postgres-store-shard.sh");
  const versionGate = source("scripts/ci/verify-postgres-version.sh");
  const pinnedPostgres =
    /image: docker\.io\/library\/postgres:18\.4-bookworm@sha256:7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568/;

  for (const job of [store, integrations]) {
    assert.match(job, pinnedPostgres);
    assert.match(job, /AUTOMATA_TEST_DATABASE_URL:/);
    assert.match(job, /postgresql-client/);
    assert.equal(
      (job.match(/\.\/scripts\/ci\/verify-postgres-version\.sh/g) ?? []).length,
      1,
      "each PostgreSQL job must run the exact version gate once",
    );
    assert.doesNotMatch(job, /sudo service postgresql|CREATE ROLE|CREATE DATABASE/);
  }
  assert.match(versionGate, /AUTOMATA_EXPECTED_POSTGRES_VERSION_NUM:-180004/);
  assert.match(versionGate, /--command='SHOW server_version_num'/);
  assert.match(versionGate, /\[\[ "\$server_version" != "\$expected_version" \]\]/);

  assert.match(store, /matrix:\n        shard: \[1, 2, 3, 4\]/);
  assert.match(
    store,
    /\.\/scripts\/ci\/run-postgres-store-shard\.sh "\$\{\{ matrix\.shard \}\}" 4/,
  );
  assert.doesNotMatch(store, /^\s+cargo test /m);
  assert.match(
    storeShard,
    /cargo metadata --format-version 1 --no-deps --locked/,
  );
  assert.match(
    storeShard,
    /package\["name"\] == "automata-ci-store"/,
  );
  assert.match(storeShard, /target\["kind"\] != \["test"\]/);
  assert.match(storeShard, /source\.count\("#\[ignore"\)/);
  assert.match(
    storeShard,
    /sorted\(weighted_targets, key=lambda item: \(-item\[1\], item\[0\]\)\)/,
  );
  assert.match(storeShard, /cargo_targets\+=\(--test "\$target"\)/);
  assert.match(storeShard, /cargo test \\\n  -p automata-ci-store \\\n  "\$\{cargo_targets\[@\]\}"/);
  assert.doesNotMatch(storeShard, /--tests|--workspace|--all-targets/);
  assert.equal((storeShard.match(/^cargo test /gm) ?? []).length, 1);

  const broadDatabasePackages = new Set([
    "automata-ci-auth-postgres",
    "automata-ci-runner-auth-postgres",
    "automata-ci-secret-postgres",
    "automata-ci-store",
  ]);
  const broadIntegrationPackages = new Set([
    "automata-ci-auth-postgres",
    "automata-ci-runner-auth-postgres",
    "automata-ci-secret-postgres",
  ]);
  const expectedCommands = [];
  for (const packageName of broadIntegrationPackages) {
    const command =
      `cargo test -p ${packageName} --tests --all-features --locked ` +
      "-- --ignored --test-threads=1";
    expectedCommands.push(command);
    assert.equal(
      integrations.split(command).length - 1,
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
      expectedCommands.push(command);
      assert.equal(
        integrations.split(command).length - 1,
        1,
        `the database-only ${packageName}/${target} suite must run exactly once`,
      );
    }
  }
  const actualCommands = (integrations.match(/^\s+cargo test .+$/gm) ?? []).map(
    (command) => command.trim(),
  );
  assert.deepEqual(
    actualCommands.sort(),
    expectedCommands.sort(),
    "PostgreSQL integration CI must contain only the inventoried database commands",
  );

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
  const verify = section(ci, "\n  verify:", "\n  rust_tests:");
  const rustTests = section(ci, "\n  rust_tests:", "\n  rust_coverage:");
  const rustCoverage = section(
    ci,
    "\n  rust_coverage:",
    "\n  renderer_tests:",
  );
  const rendererTests = section(
    ci,
    "\n  renderer_tests:",
    "\n  postgres_store:",
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
    source("scripts/ci/run-rust-coverage.sh"),
    /run_command cargo test \\\n    --workspace \\\n    --exclude automata-ci-ui-renderer \\\n    --all-targets \\\n    --all-features \\\n    --locked/,
  );
  assert.match(
    rustTests,
    /cargo test --workspace --exclude automata-ci-ui-renderer --all-targets --all-features --locked/,
  );
  assert.match(
    rustTests,
    /cargo test --workspace --exclude automata-ci-ui-renderer --doc --all-features --locked/,
  );
  assert.doesNotMatch(rustTests, /cargo-llvm-cov|run-rust-coverage\.sh/);
  assert.match(
    rustCoverage,
    /run-rust-coverage\.sh target\/coverage\/rust ordinary/,
  );
  assert.match(
    rendererTests,
    /cargo test -p automata-ci-ui-renderer --all-targets --all-features --locked/,
  );
  assert.match(
    rendererTests,
    /cargo test -p automata-ci-ui-renderer --doc --all-features --locked/,
  );
  assert.match(shellContracts, /renderer-preflight\.test\.sh/);
  assert.match(shellContracts, /renderer-provenance\.test\.sh/);
  assert.match(shellContracts, /regenerate-renderer-atomicity\.test\.sh/);
  assert.match(shellContracts, /deploy\/observability\/inventory\/\*\.sh/);
  assert.match(shellContracts, /inventory-scratch\.test\.sh/);
  assert.match(shellContracts, /release-handoff\.test\.py/);
  assert.match(shellContracts, /rust-coverage\.test\.py/);
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
  assert.match(
    source("scripts/ci/verify-product-targets.sh"),
    /scripts\/ci\/verify-documentation\.py/,
  );
});

test("repository CI omits the hosted Windows job and retains fixture parity", () => {
  const ci = source(".github/workflows/ci.yml");
  const fixture = source(
    "crates/automata-ci-workflow-github/tests/fixtures/repository-ci.yml",
  );

  assert.equal(
    fixture,
    ci,
    "the compiler fixture must exactly mirror the committed CI workflow",
  );
  assert.doesNotMatch(
    ci,
    /^  windows:[ \t]*\r?$/m,
    "the hosted Windows CI job is temporarily disabled",
  );
  assert.doesNotMatch(ci, /^[ \t]+runs-on: windows-/m);
});

test("Rust CI publishes an ordinary-lane report with a service-aware guard", () => {
  const ci = source(".github/workflows/ci.yml");
  const rustCoverage = section(
    ci,
    "\n  rust_coverage:",
    "\n  renderer_tests:",
  );
  const runner = source("scripts/ci/run-rust-coverage.sh");
  const policy = JSON.parse(source("scripts/ci/rust-coverage-policy.json"));

  assert.match(
    rustCoverage,
    /cargo install cargo-llvm-cov --version 0\.8\.7 --locked/,
  );
  assert.match(
    rustCoverage,
    /^[ \t]*\.\/scripts\/ci\/run-rust-coverage\.sh target\/coverage\/rust ordinary[ \t]*$/m,
  );
  assert.deepEqual(
    rustCoverage
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.includes("run-rust-coverage.sh")),
    ["./scripts/ci/run-rust-coverage.sh target/coverage/rust ordinary"],
  );
  assert.match(rustCoverage, /name: rust-coverage-ordinary/);
  assert.match(
    rustCoverage,
    /- name: Upload service-aware Rust coverage report\n        if: \$\{\{ always\(\) && hashFiles\('target\/coverage\/rust\/manifest\.json'\) != '' \}\}/,
  );
  assert.match(rustCoverage, /target\/coverage\/rust\/manifest\.json/);
  assert.doesNotMatch(rustCoverage, /fail-under-(?:lines|regions|functions)/);
  const expectedLanes = [
    "ordinary",
    "postgres",
    "s3",
    "podman",
    "github-live",
    "node-live",
  ];
  assert.deepEqual(Object.keys(policy.lanes), expectedLanes);
  const runnerLanes = runner.match(/known_lanes=\(([^)]*)\)/);
  assert.ok(runnerLanes, "coverage runner must declare its executable lanes");
  assert.deepEqual(runnerLanes[1].trim().split(/\s+/), expectedLanes);
  assert.ok(policy.ordinary_guard.line_percent_floor > 0);
  assert.ok(policy.lanes.postgres.source_prefixes.length > 0);
  assert.match(runner, /cargo llvm-cov show-env[\s\\]+--sh/);
  assert.match(
    runner,
    /export CARGO_TARGET_DIR="\$repository_root\/target\/llvm-cov-target"/,
  );
  assert.ok(
    runner.indexOf("export CARGO_TARGET_DIR=") <
      runner.indexOf("cargo llvm-cov show-env"),
    "coverage target isolation must be active before cargo-llvm-cov selects paths",
  );
  assert.match(runner, /--remap-path-prefix/);
  assert.equal(
    [...runner.matchAll(/cargo llvm-cov report \\\n  --remap-path-prefix/g)].length,
    2,
    "both report formats must preserve production-source filtering under remapping",
  );
  assert.match(runner, /cargo llvm-cov clean --workspace/);
  assert.match(runner, /flock --exclusive --nonblock/);
  assert.equal(
    [...runner.matchAll(/fingerprint-workspace\.py/g)].length,
    2,
    "coverage must fingerprint the complete workspace before and after collection",
  );
  assert.match(runner, /--lcov "\$coverage_stage\/coverage\.lcov"/);
  assert.ok(
    runner.indexOf("cargo llvm-cov show-env") <
      runner.indexOf("cargo llvm-cov clean --workspace"),
    "coverage environment must select the instrumented target before cleaning it",
  );
  assert.match(runner, /--lane "\$lane"/);
});

test("frontend CI retains the production-source coverage gate", () => {
  const ci = source(".github/workflows/ci.yml");
  const frontend = section(ci, "\n  frontend:", "\n  renderer:");

  assert.match(
    frontend,
    /- name: Enforce frontend coverage thresholds\n        run: npm run test:coverage/,
  );
  assert.equal(
    (frontend.match(/npm run test:coverage/g) ?? []).length,
    1,
    "the frontend job must run the coverage threshold gate exactly once",
  );
});

test("distribution build overlaps validation while the final gate retains every prerequisite", () => {
  const ci = source(".github/workflows/ci.yml");
  const renderer = section(ci, "\n  renderer:", "\n  dist_build:");
  const distBuild = section(ci, "\n  dist_build:", "\n  dist:");
  const dist = ci.slice(ci.indexOf("\n  dist:"));

  assert.match(renderer, /if: \$\{\{ github\.event_name != 'pull_request' \}\}/);
  assert.doesNotMatch(distBuild, /\n    needs:/);
  assert.match(distBuild, /name: Build static Linux distribution/);
  assert.match(distBuild, /name: Upload bootstrap distribution/);
  assert.equal(
    (
      distBuild.match(
        /service-proxy-publication\.py prepare-candidate/g,
      ) ?? []
    ).length,
    1,
    "the static build must pass its candidate through the trusted publisher policy",
  );
  assert.match(
    distBuild,
    /--candidate-commit "\$GITHUB_SHA"[\s\S]+--publisher-commit "\$GITHUB_SHA"/,
  );
  assert.match(
    dist,
    /needs:\n      - dist_build\n      - verify\n      - rust_tests\n      - rust_coverage\n      - renderer_tests\n      - postgres_store\n      - postgres_integrations\n      - frontend\n      - renderer/,
  );
  assert.match(dist, /needs\.dist_build\.result == 'success'/);
  assert.match(dist, /needs\.verify\.result == 'success'/);
  assert.match(dist, /needs\.rust_tests\.result == 'success'/);
  assert.match(dist, /needs\.rust_coverage\.result == 'success'/);
  assert.match(dist, /needs\.renderer_tests\.result == 'success'/);
  assert.match(dist, /needs\.postgres_store\.result == 'success'/);
  assert.match(dist, /needs\.postgres_integrations\.result == 'success'/);
  assert.match(dist, /needs\.frontend\.result == 'success'/);
  assert.match(
    dist,
    /needs\.renderer\.result == 'success'[\s\S]+github\.event_name == 'pull_request'[\s\S]+needs\.renderer\.result == 'skipped'/,
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
    pages,
    /- name: Upload screenshot review artifact\n        if: \$\{\{ always\(\) && hashFiles\('ui\/dist\/preview\/screenshots\/\*\.png'\) != '' \}\}/,
  );
  assert.match(
    profile,
    /group: publish-runner-profile-\$\{\{ inputs\.operation \}\}/,
  );
  assert.match(promote, /environment: profile-promotion/);
});

test("registry attestations use the isolated Docker credential home", () => {
  const profile = source(".github/workflows/profile-image.yml");
  const profileCandidate = section(profile, "\n  candidate:", "\n  promote:");
  const { candidate: serviceProxyCandidate } = serviceProxyJobs();
  const { stage } = releaseJobs();

  assertRegistryAttestationsUsePrivateHome(profileCandidate, {
    expectedCount: 3,
    home: "target/task-tmp/profile-attestation-home",
  });
  assertRegistryAttestationsUsePrivateHome(serviceProxyCandidate, {
    expectedCount: 3,
    home: "target/task-tmp/service-proxy-attestation-home",
  });
  assertRegistryAttestationsUsePrivateHome(stage, {
    expectedCount: 4,
    home: "target/task-tmp/release/attestation-home",
  });
});

test("service-proxy publication is GitHub-hosted, two-phase, and least-privileged", () => {
  const {
    candidate,
    candidateBuild,
    promote,
    promotionVerify,
    validate,
    workflow,
  } = serviceProxyJobs();

  assert.match(
    workflow,
    /group: publish-service-proxy-\$\{\{ inputs\.operation \}\}/,
  );
  assert.doesNotMatch(workflow, /runs-on: (?:self-hosted|\[[^\]]*self-hosted)/);
  for (const job of [
    validate,
    candidateBuild,
    candidate,
    promotionVerify,
    promote,
  ]) {
    assert.match(job, /runs-on: ubuntu-24\.04/);
  }
  assert.match(candidateBuild, /permissions:\n      contents: read/);
  assert.doesNotMatch(
    candidateBuild,
    /packages:|id-token:|attestations:|environment:/,
  );
  assert.match(candidate, /artifact-metadata: write/);
  assert.match(candidate, /attestations: write/);
  assert.match(candidate, /id-token: write/);
  assert.match(candidate, /packages: write/);
  assert.match(candidate, /needs: \[validate, candidate_build\]/);
  assert.match(
    promotionVerify,
    /permissions:\n      attestations: read\n      contents: read/,
  );
  assert.doesNotMatch(
    promotionVerify,
    /packages: write|id-token: write|attestations: write|environment:/,
  );
  assert.match(promote, /needs: \[validate, promotion_verify\]/);
  assert.match(promote, /environment: service-proxy-promotion/);
  assert.match(
    promote,
    /permissions:\n      contents: read\n      packages: write/,
  );
  assert.doesNotMatch(promote, /id-token: write|attestations: write/);
  assert.match(validate, /service-proxy-publication\.py validate-request/);
  assert.match(validate, /--confirmed-digest "\$CONFIRMED_DIGEST"/);
});

test("service-proxy candidates bind exact default-branch source and public digest", () => {
  const { candidate, candidateBuild } = serviceProxyJobs();
  const policy = source("scripts/ci/service-proxy-publication.py");
  const bareArtifactDigestGate =
    '[[ "$ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]';

  assert.match(candidateBuild, /ref: \$\{\{ needs\.validate\.outputs\.candidate_commit \}\}/);
  assert.match(candidateBuild, /fetch-depth: 0/);
  assert.match(candidateBuild, /fetch --force --no-tags/);
  assert.match(candidateBuild, /merge-base --is-ancestor "\$CANDIDATE_COMMIT" "\$remote_ref"/);
  assert.match(candidateBuild, /merge-base --is-ancestor "\$GITHUB_SHA" "\$remote_ref"/);
  assert.match(candidateBuild, /scripts\/ci\/build-static-musl\.sh/);
  assert.match(candidateBuild, /scripts\/ci\/prepare-service-proxy-context\.sh/);
  assert.equal(
    (candidateBuild.match(/scripts\/ci\/build-service-proxy-candidate\.sh/g) ?? [])
      .length,
    2,
  );
  assert.match(candidateBuild, /cmp --[\s\S]+service-proxy-publication-reproduction/);
  assert.match(candidateBuild, /actions\/upload-artifact@[0-9a-f]{40}/);
  assert.match(candidateBuild, /archive: false/);
  assert.equal(candidateBuild.split(bareArtifactDigestGate).length - 1, 1);
  assert.match(candidateBuild, /artifact service digest differs from candidate bytes/);
  assert.doesNotMatch(candidateBuild, /actions\/attest@|skopeo copy|GHCR_TOKEN/);
  assert.match(candidate, /Download same-run raw candidate by artifact ID/);
  assert.match(candidate, /needs\.candidate_build\.outputs\.candidate_artifact_id/);
  assert.match(candidate, /skip-decompress: true/);
  assert.match(candidate, /digest-mismatch: error/);
  assert.match(candidate, /find "\$CANDIDATE_DOWNLOAD" -mindepth 1 -maxdepth 1 -print0/);
  assert.match(candidate, /artifact-service and producer digests differ/);
  assert.match(candidate, /downloaded candidate bytes differ from both digests/);
  assert.equal(candidate.split(bareArtifactDigestGate).length - 1, 2);
  assert.doesNotMatch(
    `${candidateBuild}\n${candidate}`,
    /ARTIFACT_DIGEST#sha256:|sha256:\$\{lock_sha256\}/,
  );
  assert.match(candidate, /--source-directory "\$CANDIDATE_SOURCE_DIRECTORY"/);
  assert.match(
    policy,
    /add_argument\("--source-directory", required=True, type=pathlib\.Path\)/,
  );
  assert.doesNotMatch(policy, /add_argument\("--context"/);
  assert.doesNotMatch(
    candidate,
    /build-static-musl|prepare-service-proxy-context|build-service-proxy-candidate|verify-service-proxy-image/,
  );
  assert.match(candidate, /Refuse an existing candidate transport tag/);
  assert.match(candidate, /skopeo copy --all --preserve-digests/);
  assert.match(candidate, /oci-archive:\$\{OCI_ARCHIVE\}/);
  assert.match(candidate, /Require anonymously readable exact review candidate/);
  assert.match(candidate, /make the GHCR package public/);
  assert.equal(
    (candidate.match(/uses: actions\/attest@1e69f48acb82d1966a394da916b4c1698aa569d6/g) ?? [])
      .length,
    3,
  );
  assert.match(candidate, /predicate-type: https:\/\/cyclonedx\.org\/bom/);
  assert.match(
    candidate,
    /predicate-type: https:\/\/github\.com\/automata-ci\/automata\/attestations\/service-proxy-source-identity\/v1/,
  );
  assert.match(candidate, /Upload proposed reviewed lock/);
  assert.match(
    policy,
    /candidate-\{candidate_commit\}-[\s\S]+run-\{arguments\.run_id\}-attempt-\{arguments\.run_attempt\}/,
  );
});

test("service-proxy promotion verifies reviewed evidence before tag-only binding", () => {
  const { promote, promotionVerify } = serviceProxyJobs();
  const freshness = section(
    promote,
    "      - name: Require current default-branch identities immediately before mutation",
    "      - name: Sign in to GHCR only for tag mutation",
  );
  const immutableTag = section(
    promote,
    "      - name: Refuse moving the immutable v1 tag",
    "      - name: Bind stable tags to the locked digest without rebuilding",
  );
  const binding = section(
    promote,
    "      - name: Bind stable tags to the locked digest without rebuilding",
    "      - name: Remove registry credentials before public postcondition",
  );

  assert.match(promotionVerify, /--config "docker:\/\/\$\{LOCKED_IMAGE\}"/);
  assert.match(promotionVerify, /--signer-workflow "\$SIGNER_WORKFLOW"/);
  assert.match(promotionVerify, /--signer-digest "\$PUBLISHER_COMMIT"/);
  assert.match(promotionVerify, /--source-digest "\$PUBLISHER_COMMIT"/);
  assert.match(promotionVerify, /--source-ref "\$SOURCE_REF"/);
  assert.match(promotionVerify, /--deny-self-hosted-runners/);
  assert.match(
    promotionVerify,
    /--predicate-type https:\/\/slsa\.dev\/provenance\/v1/,
  );
  assert.equal(
    (promotionVerify.match(/gh attestation verify "\$\{common\[@\]\}"/g) ?? [])
      .length,
    3,
  );
  assert.match(
    promotionVerify,
    /service-proxy-publication\.py verify-attestations/,
  );
  assert.match(
    promotionVerify,
    /service-proxy-publication\.py verify-image-config/,
  );
  assert.match(promotionVerify, /Require public exact locked image/);
  assert.match(promotionVerify, /verify-service-proxy-image\.sh/);
  assert.match(promotionVerify, /podman pull --authfile "\$ANONYMOUS_AUTH_FILE"/);
  assert.doesNotMatch(promotionVerify, /login ghcr\.io|skopeo copy/);
  assert.doesNotMatch(
    promote,
    /gh attestation|verify-attestations|verify-image-config|verify-service-proxy-image|podman (?:pull|run)/,
  );
  assert.match(freshness, /env[\s\S]+-u GH_TOKEN[\s\S]+-u GITHUB_TOKEN/);
  assert.match(freshness, /ls-remote --exit-code --refs/);
  assert.match(freshness, /--expected-sha "\$GITHUB_SHA"/);
  assert.match(freshness, /for commit in "\$CANDIDATE_COMMIT" "\$PUBLISHER_COMMIT"/);
  assert.match(immutableTag, /"\$\{IMAGE\}:v1"/);
  assert.match(immutableTag, /refusing to move immutable v1 from/);
  assert.match(binding, /skopeo copy --all --preserve-digests/);
  assert.match(binding, /"docker:\/\/\$\{LOCKED_IMAGE\}" "docker:\/\/\$\{IMAGE\}:v1"/);
  assert.match(binding, /"docker:\/\/\$\{LOCKED_IMAGE\}" "docker:\/\/\$\{IMAGE\}:latest"/);
  assert.doesNotMatch(promote, /(?:docker|podman|buildah) build|buildx/);
  assert.ok(
    promote.indexOf("Require current default-branch identities immediately before mutation") <
      promote.indexOf("Sign in to GHCR only for tag mutation"),
  );
  assert.match(promote, /Verify anonymous promoted identities/);
  assert.match(promote, /"\$\{IMAGE\}:v1"[\s\S]+"\$\{IMAGE\}:latest"/);
});

test("service-proxy publication policy unit tests remain in the CI Node lane", () => {
  const result = spawnSync(
    "python3",
    [
      path.join(
        repositoryRoot,
        "scripts/ci/tests/service-proxy-publication.test.py",
      ),
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
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
