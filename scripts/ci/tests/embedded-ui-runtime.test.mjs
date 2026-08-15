import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { verifyEmbeddedUiRuntime } from "../lib/embedded-ui-runtime.mjs";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(testDirectory, "../../..");
const expectedPackages = [
  ["@phosphor-icons/web", "2.1.2"],
  ["react", "19.2.8"],
  ["react-dom", "19.2.8"],
  ["scheduler", "0.27.0"],
];
const policy = JSON.parse(
  readFileSync(
    path.join(repositoryRoot, "scripts/ci/third-party-license-policy.json"),
    "utf8",
  ),
);

function scratch() {
  const root = process.env.TMPDIR;
  assert.ok(root, "tests require an explicit repository-local TMPDIR");
  assert.ok(!path.resolve(root).startsWith(`${path.sep}tmp${path.sep}`));
  mkdirSync(root, { recursive: true });
  return mkdtempSync(path.join(root, "embedded-runtime-test."));
}

function fixture() {
  const root = scratch();
  const ui = path.join(root, "ui");
  const runtime = path.join(ui, "embedded-runtime");
  mkdirSync(runtime, { recursive: true });
  for (const name of ["package.json", "package-lock.json"]) {
    cpSync(path.join(repositoryRoot, "ui", name), path.join(ui, name));
    cpSync(
      path.join(repositoryRoot, "ui/embedded-runtime", name),
      path.join(runtime, name),
    );
  }
  return root;
}

function updateJson(candidate, update) {
  const document = JSON.parse(readFileSync(candidate, "utf8"));
  update(document);
  writeFileSync(candidate, `${JSON.stringify(document, null, 2)}\n`);
}

test("embedded runtime inventory matches the reviewed bundle closure", () => {
  const verified = verifyEmbeddedUiRuntime({ policy, repositoryRoot });
  assert.deepEqual(verified.packages, expectedPackages);
});

test("offline runtime SBOM contains exactly the reviewed four packages", () => {
  const verified = verifyEmbeddedUiRuntime({ policy, repositoryRoot });
  const npm = path.join(path.dirname(process.execPath), "npm");
  const result = spawnSync(
    npm,
    [
      "--prefix",
      verified.inputDirectory,
      "sbom",
      "--omit=dev",
      "--offline",
      "--package-lock-only",
      "--sbom-format",
      "cyclonedx",
      "--sbom-type",
      "application",
    ],
    { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
  );
  assert.equal(result.status, 0, result.stderr);
  const sbom = JSON.parse(result.stdout);
  const packages = sbom.components
    .map((component) => [component.name, component.version])
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  assert.deepEqual(packages, expectedPackages);
});

test("verifier rejects a weakened React peer contract", () => {
  const root = fixture();
  for (const name of ["package.json", "package-lock.json"]) {
    updateJson(path.join(root, "ui", name), (document) => {
      const manifest = name === "package.json" ? document : document.packages[""];
      manifest.peerDependencies.react = "*";
      manifest.peerDependencies["react-dom"] = "*";
    });
  }
  assert.throws(
    () => verifyEmbeddedUiRuntime({ policy, repositoryRoot: root }),
    /reviewed React peer dependency contract/,
  );
});

test("verifier rejects drift in the reviewed runtime roots", () => {
  const changedPolicy = structuredClone(policy);
  changedPolicy.npm.embeddedRuntimeRoots = ["react", "react-dom"];
  assert.throws(
    () => verifyEmbeddedUiRuntime({ policy: changedPolicy, repositoryRoot }),
    /roots differ from the reviewed direct dependency set/,
  );
});

test("verifier rejects optional ownership of an embedded dependency", () => {
  const root = fixture();
  updateJson(path.join(root, "ui/package.json"), (document) => {
    document.optionalDependencies = { react: "19.2.8" };
  });
  updateJson(path.join(root, "ui/package-lock.json"), (document) => {
    document.packages[""].optionalDependencies = { react: "19.2.8" };
  });
  assert.throws(
    () => verifyEmbeddedUiRuntime({ policy, repositoryRoot: root }),
    /must not own embedded dependency react as optional/,
  );
});

test("verifier rejects optional React peer metadata", () => {
  const root = fixture();
  for (const name of ["package.json", "package-lock.json"]) {
    updateJson(path.join(root, "ui", name), (document) => {
      const manifest = name === "package.json" ? document : document.packages[""];
      manifest.peerDependenciesMeta = {
        react: { optional: true },
        "react-dom": { optional: true },
      };
    });
  }
  assert.throws(
    () => verifyEmbeddedUiRuntime({ policy, repositoryRoot: root }),
    /must not weaken its reviewed React peer dependency contract/,
  );
});

test("verifier rejects runtime lock drift from the UI build lock", () => {
  const root = fixture();
  updateJson(
    path.join(root, "ui/embedded-runtime/package-lock.json"),
    (document) => {
      document.packages["node_modules/scheduler"].integrity = "sha512-drift";
    },
  );
  assert.throws(
    () => verifyEmbeddedUiRuntime({ policy, repositoryRoot: root }),
    /embedded package node_modules\/scheduler differs from the UI build lock/,
  );
});

test("verifier rejects packages outside the reachable runtime closure", () => {
  const root = fixture();
  updateJson(
    path.join(root, "ui/embedded-runtime/package-lock.json"),
    (document) => {
      document.packages["node_modules/unexpected"] = {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/unexpected/-/unexpected-1.0.0.tgz",
        integrity: "sha512-unexpected",
        license: "MIT",
      };
    },
  );
  assert.throws(
    () => verifyEmbeddedUiRuntime({ policy, repositoryRoot: root }),
    /contains unreachable packages/,
  );
});
