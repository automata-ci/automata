import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  assertIdenticalRegularTrees,
  collectCargoComponents,
  collectNpmComponents,
  generateThirdPartyBundles,
  hashRegularTree,
  resolveTargetChild,
  sha256,
} from "../lib/third-party-licenses.mjs";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(testDirectory, "../../..");

function scratch() {
  const root = process.env.TMPDIR;
  assert.ok(root, "tests require an explicit repository-local TMPDIR");
  assert.ok(!path.resolve(root).startsWith(`${path.sep}tmp${path.sep}`));
  mkdirSync(root, { recursive: true });
  return mkdtempSync(path.join(root, "license-test."));
}

function runChild(command, arguments_, options) {
  return new Promise((resolve, reject) => {
    const { timeoutMs = 10_000, ...spawnOptions } = options;
    const child = spawn(command, arguments_, {
      ...spawnOptions,
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", (status, signal) => {
      clearTimeout(timeout);
      resolve({ signal, status, stderr, timedOut });
    });
  });
}

async function waitForPath(candidate) {
  for (let attempt = 0; attempt < 1000; attempt += 1) {
    if (existsSync(candidate)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`timed out waiting for ${candidate}`);
}

test("Cargo traversal includes normal edges and excludes build edges", () => {
  const root = scratch();
  const dependency = path.join(root, "registry/dependency-1.0.0");
  const buildOnly = path.join(root, "registry/build-only-1.0.0");
  mkdirSync(dependency, { recursive: true });
  mkdirSync(buildOnly, { recursive: true });
  writeFileSync(path.join(dependency, "LICENSE"), "dependency license\n");
  writeFileSync(path.join(buildOnly, "LICENSE"), "build license\n");
  const packageRecord = (id, name, directory, source) => ({
    id,
    name,
    version: "1.0.0",
    source,
    license: "MIT",
    license_file: null,
    manifest_path: path.join(directory, "Cargo.toml"),
  });
  const metadata = {
    packages: [
      packageRecord("root", "product", path.join(root, "product"), null),
      packageRecord("dependency", "dependency", dependency, "registry+locked"),
      packageRecord("build", "build-only", buildOnly, "registry+locked"),
    ],
    workspace_members: ["root"],
    resolve: {
      nodes: [
        {
          id: "root",
          deps: [
            { pkg: "dependency", dep_kinds: [{ kind: null }] },
            { pkg: "build", dep_kinds: [{ kind: "build" }] },
          ],
        },
        { id: "dependency", deps: [] },
        { id: "build", deps: [] },
      ],
    },
  };
  const components = collectCargoComponents({
    metadata,
    rootName: "product",
    artifact: "product",
    repositoryRoot: root,
    vendoredPathPrefixes: [],
  });
  assert.deepEqual([...components.keys()], ["cargo:dependency@1.0.0"]);
});

test("renderer vendor preparation rejects missing or byte-different input", () => {
  const root = scratch();
  const reviewed = path.join(root, "ui/renderer/vendor");
  const prepared = path.join(root, "target/license-input/renderer/vendor");
  const reviewedPackage = path.join(reviewed, "example-1.0.0");
  mkdirSync(path.join(reviewedPackage, "src"), { recursive: true });
  writeFileSync(path.join(reviewedPackage, "Cargo.toml"), "[package]\nname='example'\n");
  writeFileSync(path.join(reviewedPackage, "src/lib.rs"), "pub fn reviewed() {}\n");
  cpSync(reviewed, prepared, { recursive: true });

  assert.doesNotThrow(() => assertIdenticalRegularTrees({
    expected: reviewed,
    actual: prepared,
    label: "renderer vendor",
  }));
  assert.equal(
    hashRegularTree(reviewed, "reviewed renderer vendor"),
    hashRegularTree(prepared, "prepared renderer vendor"),
  );

  writeFileSync(
    path.join(prepared, "example-1.0.0/src/lib.rs"),
    "pub fn tampered() {}\n",
  );
  assert.throws(
    () => assertIdenticalRegularTrees({
      expected: reviewed,
      actual: prepared,
      label: "renderer vendor",
    }),
    /does not exactly match/,
  );

  cpSync(reviewed, prepared, { recursive: true, force: true });
  rmSync(path.join(prepared, "example-1.0.0/Cargo.toml"));
  assert.throws(
    () => assertIdenticalRegularTrees({
      expected: reviewed,
      actual: prepared,
      label: "renderer vendor",
    }),
    /does not exactly match/,
  );
});

test("concurrent preparation is isolated and stages exact input before Cargo fetch", async () => {
  const fixture = scratch();
  const fakeBin = path.join(fixture, "bin");
  const scriptTmp = path.join(fixture, "script-tmp");
  const rendererInput = path.join(scriptTmp, "renderer");
  mkdirSync(fakeBin, { recursive: true });
  writeFileSync(
    path.join(fakeBin, "node"),
    [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      "if [[ \"${1:-}\" == --version ]]; then",
      "    printf 'v24.19.0\\n'",
      "    exit 0",
      "fi",
      "[[ \"${1:-}\" == \"${AUTOMATA_TEST_RUNTIME_VERIFIER}\" ]]",
      "exec \"${AUTOMATA_TEST_REAL_NODE}\" \"$@\"",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  writeFileSync(
    path.join(fakeBin, "npm"),
    [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      "if [[ \"${1:-}\" == --version ]]; then",
      "    printf '11.17.0\\n'",
      "    exit 0",
      "fi",
      "[[ $# == 6 ]]",
      "[[ \"$1\" == --prefix ]]",
      "[[ \"$2\" == \"${AUTOMATA_TEST_EMBEDDED_RUNTIME_INPUT}\" ]]",
      "[[ \"$3\" == ci ]]",
      "[[ \"$4\" == --omit=dev ]]",
      "[[ \"$5\" == --ignore-scripts ]]",
      "[[ \"$6\" == --no-audit ]]",
      "install -m 0644 -- /dev/null \"${AUTOMATA_TEST_NPM_MARKER}\"",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  writeFileSync(
    path.join(fakeBin, "cargo"),
    [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      "[[ \"${1:-}\" == fetch ]]",
      "shift",
      "manifest=",
      "while (($# > 0)); do",
      "    case \"$1\" in",
      "        --manifest-path)",
      "            manifest=\"$2\"",
      "            shift 2",
      "            ;;",
      "        *)",
      "            shift",
      "            ;;",
      "    esac",
      "done",
      "[[ -n \"${manifest}\" ]]",
      "diff --brief --recursive --no-dereference -- \\",
      "    \"${AUTOMATA_TEST_VENDOR_SOURCE}\" \\",
      "    \"$(dirname -- \"${manifest}\")/vendor\"",
      "install -m 0644 -- /dev/null \"${AUTOMATA_TEST_CARGO_MARKER}\"",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );

  const invocationCount = 16;
  const invocations = Array.from({ length: invocationCount }, (_, index) => {
    const cargoMarker = path.join(fixture, `cargo-fetch-checked-${index}`);
    const npmMarker = path.join(fixture, `npm-ci-checked-${index}`);
    return {
      cargoMarker,
      npmMarker,
      result: runChild(
        path.join(repositoryRoot, "scripts/ci/prepare-third-party-license-sources.sh"),
        [],
        {
          env: {
            ...process.env,
            AUTOMATA_TEST_CARGO_MARKER: cargoMarker,
            AUTOMATA_TEST_EMBEDDED_RUNTIME_INPUT: path.join(
              repositoryRoot,
              "ui/embedded-runtime",
            ),
            AUTOMATA_TEST_NPM_MARKER: npmMarker,
            AUTOMATA_TEST_REAL_NODE: realpathSync(process.execPath),
            AUTOMATA_TEST_RUNTIME_VERIFIER: path.join(
              repositoryRoot,
              "scripts/ci/verify-embedded-ui-runtime.mjs",
            ),
            AUTOMATA_TEST_THIRD_PARTY_LICENSE_RENDERER_INPUT: rendererInput,
            AUTOMATA_TEST_VENDOR_SOURCE: path.join(
              repositoryRoot,
              "ui/renderer/vendor",
            ),
            AUTOMATA_THIRD_PARTY_LICENSE_TEST_MODE: "1",
            PATH: `${fakeBin}:${process.env.PATH}`,
            TMPDIR: scriptTmp,
          },
        },
      ),
    };
  });
  const results = await Promise.all(
    invocations.map((invocation) => invocation.result),
  );
  for (const [index, result] of results.entries()) {
    assert.equal(result.status, 0, `invocation ${index}: ${result.stderr}`);
    assert.equal(existsSync(invocations[index].cargoMarker), true);
    assert.equal(existsSync(invocations[index].npmMarker), true);
  }
  assert.doesNotThrow(() => assertIdenticalRegularTrees({
    expected: path.join(repositoryRoot, "ui/renderer/vendor"),
    actual: path.join(rendererInput, "vendor"),
    label: "renderer vendor",
  }));
});

test("license generator waits for a complete renderer input transaction", async (t) => {
  const fixture = scratch();
  const fakeBin = path.join(fixture, "bin");
  const scriptTmp = path.join(fixture, "script-tmp");
  const rendererInput = path.join(scriptTmp, "renderer");
  const reviewedVendor = path.join(repositoryRoot, "ui/renderer/vendor");
  const preparedVendor = path.join(rendererInput, "vendor");
  const lockPath = path.join(scriptTmp, ".third-party-license-input.prepare.lock");
  const holderMarker = path.join(fixture, "exclusive-lock-held");
  const lockAttemptMarker = path.join(fixture, "shared-lock-attempted");
  const generatorMarker = path.join(fixture, "generator-observed-complete-input");
  const flockLookup = spawnSync("bash", ["-c", "command -v flock"], {
    encoding: "utf8",
  });
  assert.equal(flockLookup.status, 0, flockLookup.stderr);
  const realFlock = realpathSync(flockLookup.stdout.trim());
  mkdirSync(fakeBin, { recursive: true });
  mkdirSync(scriptTmp, { recursive: true });
  cpSync(reviewedVendor, preparedVendor, { recursive: true });
  writeFileSync(
    path.join(fakeBin, "node"),
    [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      "diff --brief --recursive --no-dereference -- \\",
      "    \"${AUTOMATA_TEST_VENDOR_SOURCE}\" \\",
      "    \"${AUTOMATA_TEST_THIRD_PARTY_LICENSE_RENDERER_INPUT}/vendor\"",
      "install -m 0644 -- /dev/null \"${AUTOMATA_TEST_GENERATOR_MARKER}\"",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  writeFileSync(
    path.join(fakeBin, "flock"),
    [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      "install -m 0644 -- /dev/null \"${AUTOMATA_TEST_FLOCK_ATTEMPT_MARKER}\"",
      "exec \"${AUTOMATA_TEST_REAL_FLOCK}\" \"$@\"",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );

  const holder = spawn(
    realFlock,
    [
      "--exclusive",
      lockPath,
      "bash",
      "-c",
      'install -m 0644 -- /dev/null "$1"; read -r _',
      "lock-holder",
      holderMarker,
    ],
    { stdio: ["pipe", "ignore", "ignore"] },
  );
  const holderExit = new Promise((resolve, reject) => {
    holder.on("error", reject);
    holder.on("close", (status, signal) => resolve({ signal, status }));
  });
  t.after(async () => {
    if (!holder.stdin.writableEnded) {
      holder.stdin.end("cleanup\n");
    }
    const cleanupTimeout = setTimeout(() => {
      holder.kill("SIGKILL");
    }, 1000);
    await holderExit;
    clearTimeout(cleanupTimeout);
  });
  await waitForPath(holderMarker);

  const missingFile = path.join(
    preparedVendor,
    "rquickjs-macro-0.10.0/Cargo.toml",
  );
  rmSync(missingFile);
  const generator = runChild(
    path.join(repositoryRoot, "scripts/ci/generate-third-party-licenses.sh"),
    [],
    {
      env: {
        ...process.env,
        AUTOMATA_TEST_FLOCK_ATTEMPT_MARKER: lockAttemptMarker,
        AUTOMATA_TEST_GENERATOR_MARKER: generatorMarker,
        AUTOMATA_TEST_REAL_FLOCK: realFlock,
        AUTOMATA_TEST_THIRD_PARTY_LICENSE_RENDERER_INPUT: rendererInput,
        AUTOMATA_TEST_VENDOR_SOURCE: reviewedVendor,
        AUTOMATA_THIRD_PARTY_LICENSE_TEST_MODE: "1",
        PATH: `${fakeBin}:${process.env.PATH}`,
        TMPDIR: scriptTmp,
      },
    },
  );
  await waitForPath(lockAttemptMarker);
  assert.equal(existsSync(generatorMarker), false);

  cpSync(
    path.join(reviewedVendor, "rquickjs-macro-0.10.0/Cargo.toml"),
    missingFile,
  );
  holder.stdin.end("release\n");
  const [holderResult, generatorResult] = await Promise.all([
    holderExit,
    generator,
  ]);
  assert.equal(holderResult.status, 0);
  assert.equal(generatorResult.status, 0, generatorResult.stderr);
  assert.equal(existsSync(generatorMarker), true);
});

test("npm traversal inventories only reachable production packages", () => {
  const root = scratch();
  const ui = path.join(root, "ui");
  for (const [name, version] of [["runtime", "1.0.0"], ["dev-only", "2.0.0"]]) {
    const directory = path.join(ui, "node_modules", name);
    mkdirSync(directory, { recursive: true });
    writeFileSync(path.join(directory, "package.json"), JSON.stringify({ name, version }));
    writeFileSync(path.join(directory, "LICENSE"), `${name} license\n`);
  }
  const lock = {
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { runtime: "1.0.0" }, devDependencies: { "dev-only": "2.0.0" } },
      "node_modules/runtime": {
        version: "1.0.0",
        integrity: "sha512-runtime",
        license: "MIT",
      },
      "node_modules/dev-only": {
        version: "2.0.0",
        integrity: "sha512-dev",
        license: "MIT",
        dev: true,
      },
    },
  };
  const components = collectNpmComponents({ lock, uiDirectory: ui, artifact: "ui" });
  assert.deepEqual([...components.keys()], ["npm:runtime@1.0.0"]);
});

test("npm traversal inventories explicit embedded dev roots and their runtime graph", () => {
  const root = scratch();
  const ui = path.join(root, "ui");
  for (const [name, version] of [
    ["embedded", "1.0.0"],
    ["transitive", "1.1.0"],
    ["unrelated", "2.0.0"],
  ]) {
    const directory = path.join(ui, "node_modules", name);
    mkdirSync(directory, { recursive: true });
    writeFileSync(path.join(directory, "package.json"), JSON.stringify({ name, version }));
    writeFileSync(path.join(directory, "LICENSE"), `${name} license\n`);
  }
  const lock = {
    lockfileVersion: 3,
    packages: {
      "": {
        devDependencies: {
          embedded: "1.0.0",
          unrelated: "2.0.0",
        },
      },
      "node_modules/embedded": {
        version: "1.0.0",
        integrity: "sha512-embedded",
        license: "MIT",
        dev: true,
        dependencies: { transitive: "1.1.0" },
      },
      "node_modules/transitive": {
        version: "1.1.0",
        integrity: "sha512-transitive",
        license: "MIT",
        dev: true,
      },
      "node_modules/unrelated": {
        version: "2.0.0",
        integrity: "sha512-unrelated",
        license: "MIT",
        dev: true,
      },
    },
  };
  const components = collectNpmComponents({
    lock,
    uiDirectory: ui,
    artifact: "ui",
    embeddedRuntimeRoots: ["embedded"],
  });
  assert.deepEqual(
    [...components.keys()],
    ["npm:embedded@1.0.0", "npm:transitive@1.1.0"],
  );
});

test("bundles are deterministic, deduplicate texts, and expose notices", () => {
  const root = scratch();
  const primary = path.join(root, "primary");
  const missing = path.join(root, "missing");
  mkdirSync(primary, { recursive: true });
  mkdirSync(missing, { recursive: true });
  writeFileSync(path.join(primary, "LICENSE"), "shared license\n");
  writeFileSync(path.join(primary, "NOTICE"), "upstream notice\n");
  mkdirSync(path.join(primary, "LICENSES"), { recursive: true });
  writeFileSync(path.join(primary, "LICENSES/MIT.txt"), "license directory text\n");
  mkdirSync(path.join(primary, "src"), { recursive: true });
  writeFileSync(path.join(primary, "src/licenses.rs"), "not legal material\n");
  mkdirSync(path.join(primary, "vendor/native"), { recursive: true });
  writeFileSync(
    path.join(primary, "vendor/native/LICENSE-VENDORED"),
    "vendored native license\n",
  );
  const make = (key, directory) => ({
    artifacts: new Set(["test"]),
    directory,
    key,
    license: "MIT",
    licenseFile: null,
    name: key,
    source: "registry+locked",
    version: "1.0.0",
  });
  const components = new Map([
    ["cargo:primary@1.0.0", make("cargo:primary@1.0.0", primary)],
    ["cargo:missing@1.0.0", make("cargo:missing@1.0.0", missing)],
  ]);
  const policy = {
    cargo: {
      allowedLicenseExpressions: ["MIT"],
      licenseFilePattern: "^(license)(?:$|[-._])",
      noticeFilePattern: "^(notice)(?:$|[-._])",
      fallbacks: [{
        components: ["cargo:missing@1.0.0"],
        licenseTextFrom: "cargo:primary@1.0.0",
        reason: "fixture workspace omits its root license",
      }],
    },
    npm: { allowedLicenseExpressions: ["MIT"], allowedProductionPackages: [] },
  };
  const options = {
    componentMaps: [components],
    inputHashes: { lock: sha256("lock") },
    policy,
    policyHash: sha256("policy"),
  };
  const first = generateThirdPartyBundles(options);
  const second = generateThirdPartyBundles(options);
  assert.deepEqual(first, second);
  assert.equal(first.licenses.match(/shared license/g)?.length, 1);
  assert.equal(first.licenses.match(/license directory text/g)?.length, 1);
  assert.doesNotMatch(first.licenses, /not legal material/);
  assert.equal(first.licenses.match(/vendored native license/g)?.length, 1);
  assert.match(first.licenses, /vendor\/native\/LICENSE-VENDORED/);
  assert.match(first.licenses, /fallback from cargo:primary@1\.0\.0/);
  assert.match(first.notices, /upstream notice/);
});

test("generation fails closed when a shipped component has no license text", () => {
  const root = scratch();
  const directory = path.join(root, "missing");
  mkdirSync(directory, { recursive: true });
  const components = new Map([
    ["cargo:missing@1.0.0", {
      artifacts: new Set(["test"]),
      directory,
      key: "cargo:missing@1.0.0",
      license: "MIT",
      licenseFile: null,
      name: "missing",
      source: "registry+locked",
      version: "1.0.0",
    }],
  ]);
  assert.throws(
    () => generateThirdPartyBundles({
      componentMaps: [components],
      inputHashes: { lock: sha256("lock") },
      policy: {
        cargo: {
          allowedLicenseExpressions: ["MIT"],
          licenseFilePattern: "^(license)(?:$|[-._])",
          noticeFilePattern: "^(notice)(?:$|[-._])",
          fallbacks: [],
        },
        npm: { allowedLicenseExpressions: ["MIT"], allowedProductionPackages: [] },
      },
      policyHash: sha256("policy"),
    }),
    /no license text found/,
  );
});

test("reviewed fallback binds exact bytes, source revision, and output attribution", () => {
  const root = scratch();
  const packageDirectory = path.join(root, "registry/missing-1.0.0");
  const reviewedDirectory = path.join(root, "scripts/ci/reviewed-license-texts");
  const reviewedPath = path.join(reviewedDirectory, "fixture.json");
  const revision = "a".repeat(40);
  const repository = "https://example.invalid/upstream";
  const licenseLines = ["Exact reviewed license", "Copyright 2021 Example"];
  const licenseBytes = Buffer.from(licenseLines.join("\n"));
  const licenseSha256 = sha256(licenseBytes);
  mkdirSync(packageDirectory, { recursive: true });
  mkdirSync(reviewedDirectory, { recursive: true });
  writeFileSync(
    path.join(packageDirectory, ".cargo_vcs_info.json"),
    JSON.stringify({ git: { sha1: revision }, path_in_vcs: "crates/missing" }),
  );
  const reviewedDocument = {
    schema: 1,
    source: repository,
    revision,
    path: "LICENSE",
    sha256: licenseSha256,
    lines: licenseLines,
  };
  writeFileSync(reviewedPath, JSON.stringify(reviewedDocument));

  const component = {
    artifacts: new Set(["test"]),
    directory: packageDirectory,
    key: "cargo:missing@1.0.0",
    license: "MIT",
    licenseFile: null,
    name: "missing",
    repository,
    source: "registry+locked",
    version: "1.0.0",
  };
  const policy = {
    cargo: {
      allowedLicenseExpressions: ["MIT"],
      licenseFilePattern: "^(license)(?:$|[-._])",
      noticeFilePattern: "^(notice)(?:$|[-._])",
      fallbacks: [],
      reviewedFallbacks: [{
        components: [{ key: component.key, pathInVcs: "crates/missing" }],
        source: component.source,
        repository,
        revision,
        licensePath: "LICENSE",
        checkedInFile: "scripts/ci/reviewed-license-texts/fixture.json",
        expectedSha256: licenseSha256,
        reason: "fixture archive omits its exact upstream license",
      }],
    },
    npm: { allowedLicenseExpressions: ["MIT"], allowedProductionPackages: [] },
  };
  const generate = () => generateThirdPartyBundles({
    componentMaps: [new Map([[component.key, component]])],
    inputHashes: { lock: sha256("lock") },
    policy,
    policyHash: sha256("policy"),
    repositoryRoot: root,
  });

  const bundles = generate();
  assert.match(bundles.licenses, /Exact reviewed license/);
  assert.match(
    bundles.licenses,
    new RegExp(
      `LICENSE sha256:${licenseSha256} \\(reviewed from ` +
        `${repository}@${revision}:LICENSE\\)`,
    ),
  );
  assert.doesNotMatch(bundles.licenses, /fallback from cargo:/);

  writeFileSync(
    reviewedPath,
    JSON.stringify({ ...reviewedDocument, lines: ["tampered license"] }),
  );
  assert.throws(generate, /reviewed license text digest changed/);

  writeFileSync(reviewedPath, JSON.stringify(reviewedDocument));
  writeFileSync(
    path.join(packageDirectory, ".cargo_vcs_info.json"),
    JSON.stringify({ git: { sha1: "b".repeat(40) }, path_in_vcs: "crates/missing" }),
  );
  assert.throws(generate, /reviewed license source revision changed/);
});

test("npm allowlist represents multiple production versions of one package", () => {
  const root = scratch();
  const components = new Map();
  for (const version of ["1.0.0", "2.0.0"]) {
    const directory = path.join(root, version);
    mkdirSync(directory, { recursive: true });
    writeFileSync(path.join(directory, "LICENSE"), `runtime ${version} license\n`);
    const key = `npm:runtime@${version}`;
    components.set(key, {
      artifacts: new Set(["ui"]),
      directory,
      key,
      license: "MIT",
      licenseFile: null,
      name: "runtime",
      source: `npm-integrity:${version}`,
      version,
    });
  }
  const bundles = generateThirdPartyBundles({
    componentMaps: [components],
    inputHashes: { lock: sha256("lock") },
    policy: {
      cargo: {
        allowedLicenseExpressions: [],
        licenseFilePattern: "^(license)(?:$|[-._])",
        noticeFilePattern: "^(notice)(?:$|[-._])",
        fallbacks: [],
      },
      npm: {
        allowedLicenseExpressions: ["MIT"],
        allowedProductionPackages: [
          { name: "runtime", version: "1.0.0" },
          { name: "runtime", version: "2.0.0" },
        ],
      },
    },
    policyHash: sha256("policy"),
  });
  assert.match(bundles.licenses, /npm:runtime@1\.0\.0/);
  assert.match(bundles.licenses, /npm:runtime@2\.0\.0/);
});

function symlinkEscapeFixture() {
  const fixture = scratch();
  const repository = path.join(fixture, "repository");
  const target = path.join(repository, "target");
  const outside = path.join(repository, "outside-target");
  mkdirSync(target, { recursive: true });
  mkdirSync(outside, { recursive: true });
  symlinkSync(outside, path.join(target, "escape"), "dir");
  return { outside, repository, target };
}

test("Node target containment rejects a child symlink escape before writing", () => {
  const { outside, repository, target } = symlinkEscapeFixture();
  assert.throws(
    () => resolveTargetChild({
      repositoryRoot: repository,
      candidate: path.join(target, "escape", "licenses"),
      label: "license output",
      create: true,
    }),
    /resolves outside/,
  );
  assert.equal(existsSync(path.join(outside, "licenses")), false);
});

test("shell target containment rejects a child symlink escape before writing", () => {
  const { outside, repository, target } = symlinkEscapeFixture();
  const helper = path.resolve(testDirectory, "../lib/target-paths.sh");
  const result = spawnSync(
    "bash",
    [
      "-c",
      [
        'source "$1"',
        'automata_init_target_root "$2"',
        'automata_canonical_target_child "$3" "fixture output"',
      ].join("\n"),
      "target-path-test",
      helper,
      repository,
      path.join(target, "escape", "licenses"),
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must resolve beneath/);
  assert.equal(existsSync(path.join(outside, "licenses")), false);
});

test("shell exact containment rejects an internal alias before destructive use", () => {
  const fixture = scratch();
  const repository = path.join(fixture, "repository");
  const target = path.join(repository, "target");
  const destination = path.join(target, "destination");
  mkdirSync(destination, { recursive: true });
  symlinkSync(destination, path.join(target, "alias"), "dir");
  const helper = path.resolve(testDirectory, "../lib/target-paths.sh");
  const result = spawnSync(
    "bash",
    [
      "-c",
      [
        'source "$1"',
        'automata_init_target_root "$2"',
        'automata_canonical_exact_target_child "$3" "wrapper source"',
      ].join("\n"),
      "exact-target-path-test",
      helper,
      repository,
      path.join(target, "alias", "source"),
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must not contain symbolic links/);
  assert.equal(existsSync(path.join(destination, "source")), false);
});

test("shell preflight rejects escaped TMPDIR before starting Node", () => {
  const { outside, repository, target } = symlinkEscapeFixture();
  const helper = path.resolve(testDirectory, "../lib/target-paths.sh");
  const escapedTmp = path.join(target, "escape", "runtime-cache");
  const result = spawnSync(
    "bash",
    [
      "-c",
      [
        "set -euo pipefail",
        'source "$1"',
        'automata_init_target_root "$2"',
        'export TMPDIR="$3"',
        'automata_set_target_tmpdir "$2" "$2/target/default-tmp"',
        'node -e \'require("node:fs").mkdirSync(process.env.TMPDIR, { recursive: true })\'',
      ].join("\n"),
      "tmpdir-preflight-test",
      helper,
      repository,
      escapedTmp,
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must resolve beneath/);
  assert.equal(existsSync(path.join(outside, "runtime-cache")), false);
});
