import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import path from "node:path";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const ignoredSourceDirectories = new Set([".git", "node_modules", "target"]);

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function hasPathEntry(candidate) {
  try {
    lstatSync(candidate);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

export function resolveTargetChild({
  repositoryRoot,
  candidate,
  label,
  create = false,
  mustExist = false,
}) {
  const canonicalRepository = realpathSync(repositoryRoot);
  const nominalTarget = path.join(canonicalRepository, "target");
  if (hasPathEntry(nominalTarget)) {
    if (lstatSync(nominalTarget).isSymbolicLink()) {
      fail("repository target directory must not be a symbolic link");
    }
    if (!lstatSync(nominalTarget).isDirectory()) {
      fail("repository target path is not a directory");
    }
  } else {
    mkdirSync(nominalTarget, { mode: 0o755 });
  }
  const canonicalTarget = realpathSync(nominalTarget);
  if (canonicalTarget !== nominalTarget) {
    fail("repository target directory must resolve inside the repository");
  }

  const absolute = path.resolve(canonicalRepository, candidate);
  if (!isInside(nominalTarget, absolute) || absolute === nominalTarget) {
    fail(`${label} must be a child of the repository target directory`);
  }

  let existingAncestor = absolute;
  while (!hasPathEntry(existingAncestor)) {
    const parent = path.dirname(existingAncestor);
    if (parent === existingAncestor) {
      fail(`cannot resolve an existing ancestor for ${label}`);
    }
    existingAncestor = parent;
  }
  const canonicalAncestor = realpathSync(existingAncestor);
  if (!isInside(canonicalTarget, canonicalAncestor)) {
    fail(`${label} resolves outside the repository target directory`);
  }

  if (create) {
    mkdirSync(absolute, { recursive: true, mode: 0o755 });
  }
  if (mustExist && !existsSync(absolute)) {
    fail(`${label} does not exist`);
  }
  if (hasPathEntry(absolute)) {
    const canonical = realpathSync(absolute);
    if (!isInside(canonicalTarget, canonical) || canonical === canonicalTarget) {
      fail(`${label} resolves outside the repository target directory`);
    }
    return canonical;
  }
  return absolute;
}

function fail(message) {
  throw new Error(message);
}

function isNormalDependency(dependency) {
  return dependency.dep_kinds.some((kind) => kind.kind === null);
}

function isInside(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..");
}

function normalizedRelativePath(root, candidate) {
  return path.relative(root, candidate).split(path.sep).join("/");
}

function cargoComponentKey(pkg) {
  return `cargo:${pkg.name}@${pkg.version}`;
}

function mergeComponent(components, candidate) {
  const existing = components.get(candidate.key);
  if (existing === undefined) {
    components.set(candidate.key, candidate);
    return;
  }
  if (
    existing.version !== candidate.version ||
    existing.license !== candidate.license ||
    existing.source !== candidate.source
  ) {
    fail(`ambiguous component identity ${candidate.key}`);
  }
  for (const artifact of candidate.artifacts) {
    existing.artifacts.add(artifact);
  }
}

export function collectCargoComponents({
  metadata,
  rootName,
  artifact,
  repositoryRoot,
  vendoredPathPrefixes,
  includeRoot = false,
  rootSource = null,
}) {
  const packages = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
  const roots = metadata.packages.filter(
    (pkg) => pkg.name === rootName && pkg.source === null,
  );
  if (roots.length !== 1) {
    fail(`expected one local Cargo package named ${rootName}; found ${roots.length}`);
  }

  const queue = [roots[0].id];
  const reachable = new Set(queue);
  while (queue.length > 0) {
    const id = queue.shift();
    const node = nodes.get(id);
    if (node === undefined) {
      fail(`Cargo metadata has no resolve node for ${id}`);
    }
    for (const dependency of node.deps) {
      if (isNormalDependency(dependency) && !reachable.has(dependency.pkg)) {
        reachable.add(dependency.pkg);
        queue.push(dependency.pkg);
      }
    }
  }

  const workspaceMembers = new Set(metadata.workspace_members);
  const components = new Map();
  for (const id of reachable) {
    const pkg = packages.get(id);
    if (pkg === undefined) {
      fail(`Cargo metadata has no package record for ${id}`);
    }
    const isRoot = id === roots[0].id;
    if (workspaceMembers.has(id) && !(includeRoot && isRoot)) {
      continue;
    }

    const packageDirectory = path.dirname(pkg.manifest_path);
    let source = pkg.source;
    if (source === null) {
      if (isRoot && includeRoot) {
        if (typeof rootSource !== "string" || rootSource.length === 0) {
          fail(`included local Cargo root ${rootName} requires a stable source label`);
        }
        source = rootSource;
      } else {
        const relative = normalizedRelativePath(repositoryRoot, packageDirectory);
        if (!vendoredPathPrefixes.some((prefix) => relative.startsWith(prefix))) {
          fail(`unreviewed local Cargo dependency ${pkg.name}@${pkg.version}: ${relative}`);
        }
        source = `vendored:${relative}`;
      }
    }
    if (typeof pkg.license !== "string" || pkg.license.length === 0) {
      fail(`Cargo dependency ${pkg.name}@${pkg.version} has no declared license`);
    }

    mergeComponent(components, {
      artifacts: new Set([artifact]),
      directory: packageDirectory,
      key: cargoComponentKey(pkg),
      license: pkg.license,
      licenseFile: pkg.license_file,
      name: pkg.name,
      source,
      version: pkg.version,
    });
  }
  return components;
}

function resolveNpmDependency(packages, uiDirectory, parentPath, dependencyName) {
  let searchDirectory = path.join(uiDirectory, parentPath);
  while (isInside(uiDirectory, searchDirectory)) {
    const candidate = normalizedRelativePath(
      uiDirectory,
      path.join(searchDirectory, "node_modules", dependencyName),
    );
    if (packages[candidate] !== undefined) {
      return candidate;
    }
    if (searchDirectory === uiDirectory) {
      break;
    }
    searchDirectory = path.dirname(searchDirectory);
  }
  return null;
}

export function collectNpmComponents({ lock, uiDirectory, artifact }) {
  if (lock.lockfileVersion !== 3 || typeof lock.packages !== "object") {
    fail("npm package-lock.json must use lockfileVersion 3");
  }
  const root = lock.packages[""];
  if (root === undefined) {
    fail("npm lockfile has no root package entry");
  }

  const queue = Object.keys(root.dependencies ?? {}).map((name) => ({
    name,
    optional: false,
    parentPath: "",
  }));
  const visited = new Set();
  const components = new Map();
  while (queue.length > 0) {
    const request = queue.shift();
    const packagePath = resolveNpmDependency(
      lock.packages,
      uiDirectory,
      request.parentPath,
      request.name,
    );
    if (packagePath === null) {
      if (request.optional) {
        continue;
      }
      fail(`cannot resolve locked npm production dependency ${request.name}`);
    }
    if (visited.has(packagePath)) {
      continue;
    }
    visited.add(packagePath);

    const entry = lock.packages[packagePath];
    if (entry.dev === true) {
      fail(`npm production dependency ${packagePath} is marked dev-only`);
    }
    const directory = path.join(uiDirectory, packagePath);
    const manifestPath = path.join(directory, "package.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest.version !== entry.version || typeof manifest.name !== "string") {
      fail(`installed npm package does not match the lock: ${packagePath}`);
    }
    const declaredLicense = entry.license ?? manifest.license;
    if (typeof declaredLicense !== "string" || declaredLicense.length === 0) {
      fail(`npm dependency ${manifest.name}@${entry.version} has no declared license`);
    }
    if (typeof entry.integrity !== "string" || entry.integrity.length === 0) {
      fail(`npm dependency ${manifest.name}@${entry.version} has no lock integrity`);
    }

    const key = `npm:${manifest.name}@${entry.version}`;
    mergeComponent(components, {
      artifacts: new Set([artifact]),
      directory,
      key,
      license: declaredLicense,
      licenseFile: null,
      name: manifest.name,
      source: `npm-integrity:${entry.integrity}`,
      version: entry.version,
    });

    for (const name of Object.keys(entry.dependencies ?? {})) {
      queue.push({ name, optional: false, parentPath: packagePath });
    }
    for (const name of Object.keys(entry.optionalDependencies ?? {})) {
      queue.push({ name, optional: true, parentPath: packagePath });
    }
    for (const name of Object.keys(entry.peerDependencies ?? {})) {
      const optional = entry.peerDependenciesMeta?.[name]?.optional === true;
      queue.push({ name, optional, parentPath: packagePath });
    }
  }
  return components;
}

function matchingFiles(directory, expression) {
  const files = [];
  const visit = (current) => {
    const entries = readdirSync(current, { withFileTypes: true }).sort((left, right) =>
      compareText(left.name, right.name),
    );
    for (const entry of entries) {
      const candidate = path.join(current, entry.name);
      if (entry.isFile() && expression.test(entry.name)) {
        files.push(candidate);
      } else if (
        entry.isDirectory() &&
        !ignoredSourceDirectories.has(entry.name)
      ) {
        visit(candidate);
      }
    }
  };
  visit(directory);
  return files;
}

function candidateFiles(component, pattern, includeExplicitLicenseFile = false) {
  const expression = new RegExp(pattern, "i");
  const candidates = matchingFiles(component.directory, expression);
  if (includeExplicitLicenseFile && component.licenseFile !== null) {
    candidates.push(
      path.isAbsolute(component.licenseFile)
        ? component.licenseFile
        : path.join(component.directory, component.licenseFile),
    );
  }
  if (candidates.length > 256) {
    fail(`too many license or notice files in ${component.key}`);
  }

  const packageRoot = realpathSync(component.directory);
  return [...new Set(candidates)]
    .map((file) => {
      const resolved = realpathSync(file);
      if (!isInside(packageRoot, resolved) || !lstatSync(resolved).isFile()) {
        fail(`license material escapes ${component.key}: ${file}`);
      }
      const bytes = readFileSync(resolved);
      if (bytes.length === 0 || bytes.length > 1024 * 1024 || bytes.includes(0)) {
        fail(`license material is empty, binary, or oversized for ${component.key}`);
      }
      new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      return {
        bytes,
        fileName: normalizedRelativePath(packageRoot, resolved),
        origin: component.key,
        sha256: sha256(bytes),
      };
    })
    .sort((left, right) => compareText(left.fileName, right.fileName));
}

function validatePolicy(components, policy) {
  const cargoAllowed = new Set(policy.cargo.allowedLicenseExpressions);
  const npmAllowed = new Set(policy.npm.allowedLicenseExpressions);
  const actualNpm = [];
  for (const component of components.values()) {
    const allowed = component.key.startsWith("cargo:") ? cargoAllowed : npmAllowed;
    if (!allowed.has(component.license)) {
      fail(`unreviewed license expression ${component.license} on ${component.key}`);
    }
    if (component.key.startsWith("npm:")) {
      actualNpm.push([component.name, component.version]);
    }
  }

  if (!Array.isArray(policy.npm.allowedProductionPackages)) {
    fail("npm production package allowlist must be an array");
  }
  const packageOrder = ([leftName, leftVersion], [rightName, rightVersion]) =>
    compareText(leftName, rightName) || compareText(leftVersion, rightVersion);
  const actualList = actualNpm.sort(packageOrder);
  const expectedList = policy.npm.allowedProductionPackages
    .map((pkg) => {
      if (typeof pkg.name !== "string" || typeof pkg.version !== "string") {
        fail("invalid npm production package allowlist entry");
      }
      return [pkg.name, pkg.version];
    })
    .sort(packageOrder);
  if (JSON.stringify(actualList) !== JSON.stringify(expectedList)) {
    fail(
      `npm production package allowlist mismatch: expected ${JSON.stringify(expectedList)}, found ${JSON.stringify(actualList)}`,
    );
  }
}

function inventoryLines(components, materialKind) {
  const lines = [];
  for (const component of components) {
    const files = component[materialKind];
    if (materialKind === "notices" && files.length === 0) {
      continue;
    }
    lines.push(`- ${component.key}`);
    lines.push(`  artifacts: ${[...component.artifacts].sort(compareText).join(", ")}`);
    lines.push(`  declared-license: ${component.license}`);
    lines.push(`  source: ${component.source}`);
    lines.push(`  ${materialKind}:`);
    for (const file of files) {
      const fallback = file.origin === component.key ? "" : ` (fallback from ${file.origin})`;
      lines.push(`    - ${file.fileName} sha256:${file.sha256}${fallback}`);
    }
  }
  return lines;
}

function uniqueTexts(components, materialKind) {
  const texts = new Map();
  for (const component of components) {
    for (const file of component[materialKind]) {
      let record = texts.get(file.sha256);
      if (record === undefined) {
        record = { bytes: file.bytes, references: [] };
        texts.set(file.sha256, record);
      } else if (!record.bytes.equals(file.bytes)) {
        fail(`SHA-256 collision while collecting ${materialKind}`);
      }
      record.references.push(`${component.key}:${file.fileName}`);
    }
  }
  return [...texts]
    .sort(([left], [right]) => compareText(left, right))
    .map(([hash, record]) => ({
      bytes: record.bytes,
      hash,
      references: [...new Set(record.references)].sort(compareText),
    }));
}

function renderBundle({ title, materialKind, components, inputHashes, policyHash }) {
  const materialLabel = materialKind === "licenses" ? "license" : "notice/copyright";
  const relevantCount = components.filter(
    (component) => component[materialKind].length > 0,
  ).length;
  const lines = [
    title,
    "",
    "This file is generated deterministically from locked dependency graphs and",
    "the exact text files shipped in their local, content-verified package sources.",
    "Cargo dev/build-only edges and npm devDependencies are not distributed and",
    "are intentionally excluded. Identical texts are stored once and referenced",
    "by SHA-256 from the component inventory.",
    "NOTICE coverage is necessarily limited to material present in the published,",
    "locked package sources; upstream-only files cannot be reconstructed offline.",
    "",
    `Policy SHA-256: ${policyHash}`,
    ...Object.entries(inputHashes)
      .sort(([left], [right]) => compareText(left, right))
      .map(([name, hash]) => `${name} SHA-256: ${hash}`),
    `Components scanned: ${components.length}`,
    `Components with ${materialLabel} material: ${relevantCount}`,
    "",
    "COMPONENT INVENTORY",
    "===================",
    ...inventoryLines(components, materialKind),
    "",
    "DEDUPLICATED VERBATIM TEXTS",
    "============================",
  ];
  let output = `${lines.join("\n")}\n`;
  for (const text of uniqueTexts(components, materialKind)) {
    output += "\n===============================================================================\n";
    output += `Text SHA-256: ${text.hash}\n`;
    output += "Referenced by:\n";
    for (const reference of text.references) {
      output += `- ${reference}\n`;
    }
    output += "-------------------------------------------------------------------------------\n";
    output += new TextDecoder("utf-8", { fatal: true }).decode(text.bytes);
    if (!output.endsWith("\n")) {
      output += "\n";
    }
  }
  return output;
}

export function generateThirdPartyBundles({
  componentMaps,
  inputHashes,
  policy,
  policyHash,
}) {
  const merged = new Map();
  for (const componentMap of componentMaps) {
    for (const component of componentMap.values()) {
      mergeComponent(merged, component);
    }
  }
  validatePolicy(merged, policy);

  const components = [...merged.values()].sort((left, right) =>
    compareText(left.key, right.key),
  );
  const fallbacks = new Map();
  for (const fallback of policy.cargo.fallbacks) {
    if (
      !Array.isArray(fallback.components) ||
      fallback.components.length === 0 ||
      typeof fallback.licenseTextFrom !== "string" ||
      typeof fallback.reason !== "string" ||
      fallback.reason.length === 0
    ) {
      fail("invalid Cargo license fallback policy entry");
    }
    for (const key of fallback.components) {
      if (fallbacks.has(key)) {
        fail(`duplicate Cargo license fallback for ${key}`);
      }
      fallbacks.set(key, fallback);
    }
  }

  const usedFallbacks = new Set();
  for (const component of components) {
    component.licenses = candidateFiles(
      component,
      policy.cargo.licenseFilePattern,
      true,
    );
    component.notices = candidateFiles(component, policy.cargo.noticeFilePattern);
  }
  const byKey = new Map(components.map((component) => [component.key, component]));
  for (const component of components) {
    if (component.licenses.length > 0) {
      continue;
    }
    const fallback = fallbacks.get(component.key);
    if (fallback === undefined) {
      fail(`no license text found for ${component.key}`);
    }
    const source = byKey.get(fallback.licenseTextFrom);
    if (source === undefined || source.licenses.length === 0) {
      fail(`license fallback source is unavailable for ${component.key}`);
    }
    component.licenses = source.licenses.map((file) => ({
      ...file,
      origin: source.key,
    }));
    usedFallbacks.add(component.key);
  }
  for (const key of fallbacks.keys()) {
    if (!usedFallbacks.has(key)) {
      fail(`stale or unused Cargo license fallback for ${key}`);
    }
  }

  for (const supplement of policy.cargo.supplements ?? []) {
    if (
      typeof supplement.component !== "string" ||
      typeof supplement.licenseTextFrom !== "string" ||
      typeof supplement.file !== "string" ||
      !/^[a-f0-9]{64}$/.test(supplement.expectedSha256 ?? "") ||
      typeof supplement.reason !== "string" ||
      supplement.reason.length === 0
    ) {
      fail("invalid Cargo supplemental license policy entry");
    }
    const component = byKey.get(supplement.component);
    const source = byKey.get(supplement.licenseTextFrom);
    if (component === undefined || source === undefined) {
      fail(`supplemental license component is unavailable: ${supplement.component}`);
    }
    const matching = source.licenses.filter(
      (file) =>
        file.fileName === supplement.file &&
        file.sha256 === supplement.expectedSha256,
    );
    if (matching.length !== 1) {
      fail(`supplemental license source changed for ${supplement.component}`);
    }
    component.licenses.push({ ...matching[0], origin: source.key });
    component.licenses.sort((left, right) => compareText(left.fileName, right.fileName));
  }

  return {
    licenses: renderBundle({
      title: "AUTOMATA THIRD-PARTY LICENSES",
      materialKind: "licenses",
      components,
      inputHashes,
      policyHash,
    }),
    notices: renderBundle({
      title: "AUTOMATA THIRD-PARTY NOTICES AND COPYRIGHTS",
      materialKind: "notices",
      components,
      inputHashes,
      policyHash,
    }),
  };
}
