// Internal implementation. Invoke generate-third-party-licenses.sh so TMPDIR
// and the shared renderer-input lock are established before Node starts.

import { execFileSync } from "node:child_process";
import {
  chmodSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertIdenticalRegularTrees,
  collectCargoComponents,
  collectNpmComponents,
  generateThirdPartyBundles,
  hashRegularTree,
  resolveTargetChild,
  sha256,
} from "./lib/third-party-licenses.mjs";

const expectedNodeVersion = "v24.19.0";
const target = "x86_64-unknown-linux-musl";
const rendererTarget = "wasm32-wasip2";

function fail(message) {
  throw new Error(message);
}

function cargoMetadata(arguments_) {
  const output = execFileSync("cargo", ["metadata", ...arguments_], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "inherit"],
  });
  return JSON.parse(output);
}

function writeReadOnlyOutput(outputDirectory, name, contents) {
  const destination = path.join(outputDirectory, name);
  const temporary = path.join(outputDirectory, `.${name}.${process.pid}.new`);
  try {
    writeFileSync(temporary, contents, { flag: "wx", mode: 0o644 });
    renameSync(temporary, destination);
    chmodSync(destination, 0o444);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function main() {
  if (process.version !== expectedNodeVersion) {
    fail(`Node.js ${expectedNodeVersion.slice(1)} is required; found ${process.version}`);
  }
  if (process.argv.length > 3) {
    fail("usage: generate-third-party-licenses.sh [OUTPUT_DIRECTORY]");
  }

  const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
  const repositoryRoot = realpathSync(path.join(scriptDirectory, "../.."));
  const outputDirectory = resolveTargetChild({
    repositoryRoot,
    candidate: process.argv[2] ?? "target/distribution-input/licenses",
    label: "license output",
    create: true,
  });
  const scratch = process.env.TMPDIR;
  if (scratch === undefined) {
    fail("TMPDIR must be an explicit repository-local target directory");
  }
  process.env.TMPDIR = resolveTargetChild({
    repositoryRoot,
    candidate: scratch,
    label: "TMPDIR",
    create: true,
  });

  const policyPath = path.join(scriptDirectory, "third-party-license-policy.json");
  const workspaceLockPath = path.join(repositoryRoot, "Cargo.lock");
  const rendererLockPath = path.join(
    repositoryRoot,
    "ui/renderer/wrapper.Cargo.lock",
  );
  const npmLockPath = path.join(repositoryRoot, "ui/package-lock.json");
  const rendererInputDirectory = resolveTargetChild({
    repositoryRoot,
    candidate:
      process.env.AUTOMATA_INTERNAL_THIRD_PARTY_LICENSE_RENDERER_INPUT ??
      "target/third-party-license-input/renderer",
    label: "renderer license input",
    mustExist: true,
  });
  const rendererVendorSourceDirectory = path.join(
    repositoryRoot,
    "ui/renderer/vendor",
  );
  const rendererVendorInputDirectory = path.join(
    rendererInputDirectory,
    "vendor",
  );
  for (const required of [
    path.join(rendererInputDirectory, "Cargo.toml"),
    path.join(rendererInputDirectory, "Cargo.lock"),
    path.join(rendererInputDirectory, "LICENSE-MIT"),
    path.join(rendererInputDirectory, "src/lib.rs"),
  ]) {
    readFileSync(required);
  }
  if (
    !readFileSync(path.join(rendererInputDirectory, "Cargo.toml")).equals(
      readFileSync(path.join(repositoryRoot, "ui/renderer/wrapper.Cargo.toml")),
    ) ||
    !readFileSync(path.join(rendererInputDirectory, "Cargo.lock")).equals(
      readFileSync(rendererLockPath),
    ) ||
    !readFileSync(path.join(rendererInputDirectory, "LICENSE-MIT")).equals(
      readFileSync(path.join(repositoryRoot, "LICENSE")),
    )
  ) {
    fail("renderer license input is stale; run prepare-third-party-license-sources.sh");
  }
  assertIdenticalRegularTrees({
    expected: rendererVendorSourceDirectory,
    actual: rendererVendorInputDirectory,
    label: "renderer vendor",
  });

  const policyBytes = readFileSync(policyPath);
  const policy = JSON.parse(policyBytes.toString("utf8"));
  if (policy.schema !== 1) {
    fail("unsupported third-party license policy schema");
  }

  const commonMetadataArguments = [
    "--locked",
    "--offline",
    "--format-version=1",
  ];
  const workspaceMetadata = cargoMetadata([
    ...commonMetadataArguments,
    "--all-features",
    "--filter-platform",
    target,
    "--manifest-path",
    path.join(repositoryRoot, "Cargo.toml"),
  ]);
  const rendererMetadata = cargoMetadata([
    ...commonMetadataArguments,
    "--manifest-path",
    path.join(rendererInputDirectory, "Cargo.toml"),
    "--no-default-features",
    "--features",
    "p2,encoding",
    "--filter-platform",
    rendererTarget,
  ]);

  const cargoOptions = {
    repositoryRoot,
    vendoredPathPrefixes: policy.cargo.vendoredPathPrefixes,
  };
  const componentMaps = [
    collectCargoComponents({
      ...cargoOptions,
      metadata: workspaceMetadata,
      rootName: "automata",
      artifact: "automata",
    }),
    collectCargoComponents({
      ...cargoOptions,
      metadata: workspaceMetadata,
      rootName: "automata-runner",
      artifact: "automata-runner",
    }),
    collectCargoComponents({
      ...cargoOptions,
      metadata: rendererMetadata,
      rootName: "renderer",
      artifact: "embedded-renderer",
      vendoredPathMappings: [{
        prepared: rendererVendorInputDirectory,
        reviewed: rendererVendorSourceDirectory,
      }],
      includeRoot: true,
      rootSource: "generated:wasm-rquickjs-cli@0.4.1+automata-ui",
    }),
    collectNpmComponents({
      lock: JSON.parse(readFileSync(npmLockPath, "utf8")),
      uiDirectory: path.join(repositoryRoot, "ui"),
      artifact: "embedded-ui-runtime",
    }),
  ];

  const bundles = generateThirdPartyBundles({
    componentMaps,
    inputHashes: {
      "Cargo.lock": sha256(readFileSync(workspaceLockPath)),
      "ui/package-lock.json": sha256(readFileSync(npmLockPath)),
      "ui/renderer/wrapper.Cargo.lock": sha256(readFileSync(rendererLockPath)),
      "ui/renderer/vendor": hashRegularTree(
        rendererVendorSourceDirectory,
        "renderer vendor reviewed source",
      ),
    },
    policy,
    policyHash: sha256(policyBytes),
    repositoryRoot,
  });
  writeReadOnlyOutput(
    outputDirectory,
    "THIRD_PARTY_LICENSES.txt",
    bundles.licenses,
  );
  writeReadOnlyOutput(
    outputDirectory,
    "THIRD_PARTY_NOTICES.txt",
    bundles.notices,
  );
  console.log(`Created deterministic third-party license bundle in ${outputDirectory}`);
}

main();
