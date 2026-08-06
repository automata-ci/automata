import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  collectCargoComponents,
  collectNpmComponents,
  generateThirdPartyBundles,
  resolveTargetChild,
  sha256,
} from "../lib/third-party-licenses.mjs";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));

function scratch() {
  const root = process.env.TMPDIR;
  assert.ok(root, "tests require an explicit repository-local TMPDIR");
  assert.ok(!path.resolve(root).startsWith(`${path.sep}tmp${path.sep}`));
  mkdirSync(root, { recursive: true });
  return mkdtempSync(path.join(root, "license-test."));
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

test("bundles are deterministic, deduplicate texts, and expose notices", () => {
  const root = scratch();
  const primary = path.join(root, "primary");
  const missing = path.join(root, "missing");
  mkdirSync(primary, { recursive: true });
  mkdirSync(missing, { recursive: true });
  writeFileSync(path.join(primary, "LICENSE"), "shared license\n");
  writeFileSync(path.join(primary, "NOTICE"), "upstream notice\n");
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
