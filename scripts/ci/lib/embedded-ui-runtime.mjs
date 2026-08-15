import {
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";

const directRuntimeDependencies = [
  "@phosphor-icons/web",
  "react",
  "react-dom",
];
const reviewedPeerDependencies = {
  react: "^19.2.0",
  "react-dom": "^19.2.0",
};
const reviewedRuntimeIdentity = {
  engines: { node: "24.19.0" },
  license: "MIT",
  name: "@automata/embedded-ui-runtime",
  private: true,
  version: "0.0.0",
};

function compareText(left, right) {
  if (left < right) {
    return -1;
  }
  return left > right ? 1 : 0;
}

function comparePackage([leftName, leftVersion], [rightName, rightVersion]) {
  return compareText(leftName, rightName) || compareText(leftVersion, rightVersion);
}

function fail(message) {
  throw new Error(message);
}

function record(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function optionalRecord(value, label) {
  return value === undefined ? {} : record(value, label);
}

function readRegularFile(candidate, label) {
  let metadata;
  try {
    metadata = lstatSync(candidate);
  } catch {
    fail(`${label} is missing`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    fail(`${label} must be a regular non-symbolic file`);
  }
  return readFileSync(candidate);
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(`${label} is not valid JSON`);
  }
}

function assertEqual(actual, expected, message) {
  if (!isDeepStrictEqual(actual, expected)) {
    fail(message);
  }
}

function assertLockDocument(lock, manifest, label) {
  assertEqual(
    Object.keys(lock).sort(),
    ["lockfileVersion", "name", "packages", "requires", "version"].sort(),
    `${label} must retain its exact lockfileVersion 3 document shape`,
  );
  if (
    lock.lockfileVersion !== 3 ||
    lock.name !== manifest.name ||
    lock.version !== manifest.version ||
    lock.requires !== true
  ) {
    fail(`${label} identity differs from its manifest`);
  }
}

function packageName(packagePath) {
  const marker = "node_modules/";
  const index = packagePath.lastIndexOf(marker);
  if (index < 0) {
    fail(`invalid npm lock package path ${packagePath}`);
  }
  const suffix = packagePath.slice(index + marker.length);
  const parts = suffix.split("/");
  const name = suffix.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
  if (name.length === 0) {
    fail(`invalid npm lock package path ${packagePath}`);
  }
  return name;
}

function resolveDependency(packages, parentPath, name) {
  let searchPath = parentPath;
  while (true) {
    const candidate = path.posix.join(searchPath, "node_modules", name);
    if (packages[candidate] !== undefined) {
      return candidate;
    }
    if (searchPath.length === 0) {
      return null;
    }
    searchPath = path.posix.dirname(searchPath);
    if (searchPath === ".") {
      searchPath = "";
    }
  }
}

function enqueueDependencies(queue, packagePath, packageRecord) {
  for (const name of Object.keys(packageRecord.dependencies ?? {})) {
    queue.push({ name, optional: false, parentPath: packagePath });
  }
  for (const name of Object.keys(packageRecord.optionalDependencies ?? {})) {
    queue.push({ name, optional: true, parentPath: packagePath });
  }
  for (const name of Object.keys(packageRecord.peerDependencies ?? {})) {
    queue.push({
      name,
      optional: packageRecord.peerDependenciesMeta?.[name]?.optional === true,
      parentPath: packagePath,
    });
  }
}

function lockedRuntimePackages(lock) {
  if (lock.lockfileVersion !== 3) {
    fail("embedded UI runtime lock must use lockfileVersion 3");
  }
  const packages = record(lock.packages, "embedded UI runtime lock packages");
  const root = record(packages[""], "embedded UI runtime lock root");
  const queue = [];
  enqueueDependencies(queue, "", root);
  const reachable = new Map();

  while (queue.length > 0) {
    const request = queue.shift();
    const packagePath = resolveDependency(
      packages,
      request.parentPath,
      request.name,
    );
    if (packagePath === null) {
      if (request.optional) {
        continue;
      }
      fail(`embedded UI runtime lock cannot resolve ${request.name}`);
    }
    if (reachable.has(packagePath)) {
      continue;
    }
    const dependency = record(
      packages[packagePath],
      `embedded UI runtime lock package ${packagePath}`,
    );
    if (packageName(packagePath) !== request.name) {
      fail(`embedded UI runtime lock aliases ${request.name} to ${packagePath}`);
    }
    if (
      typeof dependency.version !== "string" ||
      typeof dependency.integrity !== "string" ||
      typeof dependency.resolved !== "string" ||
      dependency.dev === true
    ) {
      fail(`embedded UI runtime lock has an invalid production package ${packagePath}`);
    }
    reachable.set(packagePath, {
      name: request.name,
      packagePath,
      record: dependency,
      version: dependency.version,
    });
    enqueueDependencies(queue, packagePath, dependency);
  }

  const lockedPaths = Object.keys(packages).filter((entry) => entry.length > 0);
  assertEqual(
    [...reachable.keys()].sort(),
    lockedPaths.sort(),
    "embedded UI runtime lock contains unreachable packages",
  );
  return { packages, reachable, root };
}

function comparableLockRecord(packageRecord) {
  const comparable = { ...packageRecord };
  delete comparable.dev;
  return comparable;
}

function allowedRuntimePackages(policy) {
  const allowed = policy?.npm?.allowedProductionPackages;
  if (!Array.isArray(allowed)) {
    fail("npm production package allowlist must be an array");
  }
  return allowed.map((entry) => {
    if (
      entry === null ||
      typeof entry !== "object" ||
      typeof entry.name !== "string" ||
      typeof entry.version !== "string"
    ) {
      fail("invalid npm production package allowlist entry");
    }
    return [entry.name, entry.version];
  }).sort(comparePackage);
}

function embeddedRuntimeRoots(policy) {
  const roots = policy?.npm?.embeddedRuntimeRoots;
  if (
    !Array.isArray(roots) ||
    roots.length === 0 ||
    roots.some((name) => typeof name !== "string" || name.length === 0) ||
    new Set(roots).size !== roots.length
  ) {
    fail("npm policy must define unique embedded runtime roots");
  }
  assertEqual(
    [...roots].sort(),
    [...directRuntimeDependencies].sort(),
    "npm embedded runtime roots differ from the reviewed direct dependency set",
  );
  return roots;
}

export function verifyEmbeddedUiRuntime({ policy, repositoryRoot }) {
  const canonicalRoot = realpathSync(repositoryRoot);
  const uiDirectory = path.join(canonicalRoot, "ui");
  const inputDirectory = path.join(uiDirectory, "embedded-runtime");
  let inputMetadata;
  try {
    inputMetadata = lstatSync(inputDirectory);
  } catch {
    fail("embedded UI runtime input is missing");
  }
  if (
    !inputMetadata.isDirectory() ||
    inputMetadata.isSymbolicLink() ||
    realpathSync(inputDirectory) !== inputDirectory
  ) {
    fail("embedded UI runtime input must be a real repository directory");
  }

  const uiManifestPath = path.join(uiDirectory, "package.json");
  const uiLockPath = path.join(uiDirectory, "package-lock.json");
  const manifestPath = path.join(inputDirectory, "package.json");
  const lockPath = path.join(inputDirectory, "package-lock.json");
  const uiManifestBytes = readRegularFile(uiManifestPath, "UI package.json");
  const uiLockBytes = readRegularFile(uiLockPath, "UI package-lock.json");
  const manifestBytes = readRegularFile(
    manifestPath,
    "embedded UI runtime package.json",
  );
  const lockBytes = readRegularFile(
    lockPath,
    "embedded UI runtime package-lock.json",
  );
  const uiManifest = record(
    parseJson(uiManifestBytes, "UI package.json"),
    "UI package.json",
  );
  const uiLock = record(
    parseJson(uiLockBytes, "UI package-lock.json"),
    "UI package-lock.json",
  );
  const manifest = record(
    parseJson(manifestBytes, "embedded UI runtime package.json"),
    "embedded UI runtime package.json",
  );
  const lock = record(
    parseJson(lockBytes, "embedded UI runtime package-lock.json"),
    "embedded UI runtime package-lock.json",
  );
  const runtimeRoots = embeddedRuntimeRoots(policy);

  assertEqual(
    {
      engines: manifest.engines,
      license: manifest.license,
      name: manifest.name,
      private: manifest.private,
      version: manifest.version,
    },
    reviewedRuntimeIdentity,
    "embedded UI runtime manifest must retain its reviewed private identity",
  );
  assertLockDocument(lock, manifest, "embedded UI runtime lock");
  const dependencies = record(
    manifest.dependencies,
    "embedded UI runtime dependencies",
  );
  assertEqual(
    Object.keys(dependencies).sort(),
    [...runtimeRoots].sort(),
    "embedded UI runtime manifest must own the exact direct dependency set",
  );
  for (const section of [
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    if (manifest[section] !== undefined) {
      fail(`embedded UI runtime manifest must not declare ${section}`);
    }
  }

  const uiDependencies = optionalRecord(
    uiManifest.dependencies,
    "UI production dependencies",
  );
  const uiDevDependencies = record(
    uiManifest.devDependencies,
    "UI development dependencies",
  );
  const uiOptionalDependencies = optionalRecord(
    uiManifest.optionalDependencies,
    "UI optional dependencies",
  );
  const uiPeerDependencies = record(
    uiManifest.peerDependencies,
    "UI peer dependencies",
  );
  for (const name of directRuntimeDependencies) {
    if (uiDependencies[name] !== undefined) {
      fail(`UI package must not own embedded dependency ${name} as production`);
    }
    if (uiDevDependencies[name] !== dependencies[name]) {
      fail(`embedded UI runtime ${name} differs from the UI build dependency`);
    }
    if (uiOptionalDependencies[name] !== undefined) {
      fail(`UI package must not own embedded dependency ${name} as optional`);
    }
  }
  assertEqual(
    uiPeerDependencies,
    reviewedPeerDependencies,
    "UI package must retain its reviewed React peer dependency contract",
  );
  const uiPeerDependenciesMeta = optionalRecord(
    uiManifest.peerDependenciesMeta,
    "UI peer dependency metadata",
  );
  assertEqual(
    uiPeerDependenciesMeta,
    {},
    "UI package must not weaken its reviewed React peer dependency contract",
  );
  for (const section of ["bundleDependencies", "bundledDependencies"]) {
    if (uiManifest[section] !== undefined) {
      fail(`UI package must not declare ${section}`);
    }
  }

  assertLockDocument(uiLock, uiManifest, "UI lock");
  const uiLockPackages = record(uiLock.packages, "UI lock packages");
  const uiLockRoot = record(uiLockPackages[""], "UI lock root");
  assertEqual(
    {
      engines: uiLockRoot.engines,
      license: uiLockRoot.license,
      name: uiLockRoot.name,
      version: uiLockRoot.version,
    },
    {
      engines: uiManifest.engines,
      license: uiManifest.license,
      name: uiManifest.name,
      version: uiManifest.version,
    },
    "UI manifest and lock identity differ",
  );
  assertEqual(
    optionalRecord(uiLockRoot.dependencies, "UI lock production dependencies"),
    uiDependencies,
    "UI manifest and lock production dependencies differ",
  );
  assertEqual(
    uiLockRoot.devDependencies,
    uiManifest.devDependencies,
    "UI manifest and lock development dependencies differ",
  );
  assertEqual(
    optionalRecord(uiLockRoot.optionalDependencies, "UI lock optional dependencies"),
    uiOptionalDependencies,
    "UI manifest and lock optional dependencies differ",
  );
  assertEqual(
    uiLockRoot.peerDependencies,
    uiManifest.peerDependencies,
    "UI manifest and lock peer dependencies differ",
  );
  assertEqual(
    optionalRecord(
      uiLockRoot.peerDependenciesMeta,
      "UI lock peer dependency metadata",
    ),
    {},
    "UI lock must not weaken the reviewed React peer dependency contract",
  );
  for (const section of ["bundleDependencies", "bundledDependencies"]) {
    if (uiLockRoot[section] !== undefined) {
      fail(`UI lock must not declare ${section}`);
    }
  }

  const inventory = lockedRuntimePackages(lock);
  assertEqual(
    inventory.root,
    {
      name: manifest.name,
      version: manifest.version,
      license: manifest.license,
      dependencies,
      engines: manifest.engines,
    },
    "embedded UI runtime manifest and lock root differ",
  );
  for (const name of directRuntimeDependencies) {
    const component = [...inventory.reachable.values()].find(
      (candidate) => candidate.name === name,
    );
    if (component === undefined || component.version !== dependencies[name]) {
      fail(`embedded UI runtime ${name} is not pinned to its exact locked version`);
    }
  }
  for (const [packagePath, component] of inventory.reachable) {
    const bundled = uiLockPackages[packagePath];
    if (bundled === undefined) {
      fail(`UI build lock does not contain embedded package ${packagePath}`);
    }
    assertEqual(
      comparableLockRecord(component.record),
      comparableLockRecord(bundled),
      `embedded package ${packagePath} differs from the UI build lock`,
    );
  }

  const actualPackages = [...inventory.reachable.values()]
    .map((component) => [component.name, component.version])
    .sort(comparePackage);
  assertEqual(
    actualPackages,
    allowedRuntimePackages(policy),
    "embedded UI runtime packages differ from the npm production allowlist",
  );

  return {
    embeddedRuntimeRoots: runtimeRoots,
    inputDirectory,
    lock,
    lockBytes,
    lockPath,
    manifest,
    manifestBytes,
    manifestPath,
    packages: actualPackages,
    uiLockBytes,
    uiLockPath,
    uiManifestBytes,
    uiManifestPath,
  };
}
